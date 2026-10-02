import { Banner } from "../ui/components";
import { useApp } from "../runtime/AppProvider";

/** The status banners every catalog-backed screen shows: demo data, "catalog
 * out of date" (a fetched manifest failed verification and was not applied,
 * build plan §3.5) and "saved catalog could not be verified". */
export function CatalogBanners() {
  const { isDemo, catalogState, refreshCatalog, t } = useApp();
  return (
    <>
      {isDemo ? <Banner tone="info" text={t("banner.demo")} /> : null}
      {catalogState.outOfDateBanner ? (
        <Banner text={t("banner.outOfDate")} actionLabel={t("banner.outOfDate.action")} onAction={() => void refreshCatalog()} />
      ) : null}
      {catalogState.cacheDropped ? <Banner text={t("catalog.dropped")} /> : null}
    </>
  );
}
