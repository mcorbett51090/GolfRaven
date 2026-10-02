-- 0029_install_link_pseudonym_domain.sql
-- P3f gate finding P1 (MEDIUM). 0027's private.account_pseudonyms computed
-- hmac(user_id::text, key) with the SAME vault key and the SAME input as
-- app.attestation.player_pseudonym (0004/0018/0022), so:
--   (a) a deleted player's install-link tombstone joined to their retained
--       staff-attestation rows by plain equality, and
--   (b) service_role (EXECUTE on account_pseudonyms) held an oracle for
--       attestation pseudonyms: account_pseudonyms(uid) == player_pseudonym.
-- Fix: DOMAIN SEPARATION. The input is now 'install_link_account:' || user_id,
-- so the same key can no longer produce a value that equals, or can be joined
-- to, any other pseudonym scheme's output.
--
-- Also: the "preferred" key (the one NEW rows are written under) was
-- v.name = max(v.name) — lexicographic, so 'pseudonym_hmac_v9' beat '..._v10'.
-- It is now the NEWEST key in the vault's own creation order (vault
-- created_at DESC), ties broken by the numeric version suffix, then by name. (The
-- key registry only lists keys already USED to write a row, so a freshly added
-- key is not in it yet; the vault is the authority on which key is newest.)
--
-- EXISTING ROWS. Rows already in app.install_link_account were written with the
-- OLD derivation and cannot be recomputed (the table holds no user id, by
-- design), and they would stay equality-joinable to attestation pseudonyms —
-- exactly the defect. They are therefore DELETED here. Justification: nothing is
-- deployed (0027 is not yet live in any environment), so no fraud mark or count
-- is lost; and "keep them" would knowingly retain the join this migration exists
-- to remove. Live `device` rows keep the count/fraud signals meanwhile (the
-- substitute reads both sources), and each account's tombstone is rewritten, under
-- the new derivation, on its next activation.
--
-- Rotation semantics are unchanged from 0027: record_install_link skips an
-- account already recorded under ANY active key (so one account is not counted
-- twice), because account_pseudonyms still returns one pseudonym per active key.
--
-- Same signature, same grants (CREATE OR REPLACE keeps them), same inventory row
-- and same owner; plain redefinition under the 0020/0022 ownership bracket.

-- FORCE-RLS table with no policy for this role: the same temporary
-- CURRENT_USER-scoped policy dance 0017/0022/0028 use.
CREATE POLICY current_user_purge_install_link_account_0029 ON app.install_link_account
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
DELETE FROM app.install_link_account;
DROP POLICY current_user_purge_install_link_account_0029 ON app.install_link_account;

-- The creation order lives in vault.decrypted_secrets.created_at, which 0018's
-- narrow column grant to private_definer (id, name, decrypted_secret) does not
-- include: one more column, same view, same role — a timestamp, not a secret.
GRANT SELECT (created_at) ON vault.decrypted_secrets TO private_definer;

GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.account_pseudonyms(p_user_id uuid)
RETURNS TABLE (key_id uuid, pseudonym text, preferred boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'account_pseudonyms: p_user_id must not be NULL' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM vault.decrypted_secrets
    WHERE name LIKE 'pseudonym_hmac%' AND (decrypted_secret IS NULL OR length(decrypted_secret) < 32)
  ) OR NOT EXISTS (SELECT 1 FROM vault.decrypted_secrets WHERE name LIKE 'pseudonym_hmac%') THEN
    RAISE EXCEPTION 'account_pseudonyms: no valid (>=32 byte) pseudonym_hmac key in vault.decrypted_secrets' USING ERRCODE = '55000';
  END IF;
  RETURN QUERY
    SELECT v.id,
           encode(public.hmac('install_link_account:' || p_user_id::text, v.decrypted_secret, 'sha256'), 'hex'),
           row_number() OVER (
             ORDER BY v.created_at DESC,
                      coalesce(nullif(regexp_replace(v.name, '\D', '', 'g'), '')::numeric, -1) DESC,
                      v.name DESC
           ) = 1
    FROM vault.decrypted_secrets v
    WHERE v.name LIKE 'pseudonym_hmac%';
END;
$$;

COMMENT ON FUNCTION private.account_pseudonyms(uuid) IS
  'Vault-keyed HMAC pseudonym of an account id for the install-link tombstone, under every active pseudonym_hmac key; the input is DOMAIN-SEPARATED (''install_link_account:'' || user_id) so it never equals app.attestation.player_pseudonym (0029, gate P1). `preferred` = the newest key by vault creation order (numeric version suffix, then name, as tie-breaks).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;
