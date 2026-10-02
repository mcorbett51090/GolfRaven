import { isTrustStateCorrupt } from "../catalog/manager";
import { Banner } from "../ui/components";
import { useApp } from "../runtime/AppProvider";

/** The status banners every catalog-backed screen shows: demo data, "catalog
 * out of date" (a fetched manifest failed verification and was not applied,
 * build plan §3.5) and "saved catalog could not be verified". When the install's
 * own trust state is unreadable (`TRUST_STATE_CORRUPT`) a dedicated message
 * REPLACES those two — "check again" cannot fix it — and points at Me → Reset
 * catalog data. */
export function CatalogBanners() {
  const { isDemo, catalogState, refreshCatalog, t } = useApp();
  const corrupt = isTrustStateCorrupt(catalogState);
  return (
    <>
      {isDemo ? <Banner tone="info" text={t("banner.demo")} /> : null}
      {corrupt ? <Banner text={t("banner.trustCorrupt")} /> : null}
      {!corrupt && catalogState.outOfDateBanner ? (
        <Banner text={t("banner.outOfDate")} actionLabel={t("banner.outOfDate.action")} onAction={() => void refreshCatalog()} />
      ) : null}
      {!corrupt && catalogState.cacheDropped ? <Banner text={t("catalog.dropped")} /> : null}
    </>
  );
}
