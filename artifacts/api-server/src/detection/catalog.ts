/**
 * Aggregated rule catalog for the full ARGUS detection surface.
 * The detections route returns this combined list so the frontend (and API
 * consumers) can present and filter every active rule across all domains
 * (PROC / NET / FILE) from a single endpoint.
 */

import { RULE_CATALOG as PROC_CATALOG } from "./rules";
import { NET_RULE_CATALOG } from "./network/rules";
import { FILE_RULE_CATALOG } from "./file/rules";

/** Rule catalog entries shared by every detection domain. */
export type RuleCatalogEntry = {
  rule_id: string;
  rule_name: string;
  description: string;
};

/**
 * The full set of detection rules the API server can produce, ordered by domain
 * prefix (PROC, NET, FILE). The size of this list is asserted in the API test
 * suite so new rules added in other phases must be added here.
 */
export const ALL_RULE_CATALOG: RuleCatalogEntry[] = [
  ...PROC_CATALOG,
  ...NET_RULE_CATALOG,
  ...FILE_RULE_CATALOG,
];