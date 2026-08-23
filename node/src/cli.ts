export {
  api,
  apiOptional,
  approveClientEnrollment,
  completeRecovery,
  doctorE2ee,
  downloadFile,
  fetchGithubOidcToken,
  getCirclesToken,
  getConfig,
  getConfigForVltOwner,
  listClients,
  rawApi,
  rawSecretsApi,
  requestClientEnrollment,
  resolveItem,
  resolveVault,
  revokeClient,
  secretsApi,
  secretsApiForOwner,
  setOverrides,
  startRecovery,
  uploadFile,
} from "./api"
export {
  handleApi,
  handleSecretsApi,
  VaultApiError,
  type ClientSummary,
  type EnrollmentApprovalDetails,
  type EnrollmentApprovalResult,
  type EnrollmentRequestResult,
  type VaultConfig,
} from "./e2ee-client"
export { encodeBase64 } from "./e2ee-crypto"
export {
  formatFingerprint,
  MAX_CLIENT_NAME_LENGTH,
  normalizeVaultOrigin,
  type EnrollmentRequest,
} from "./client-enrollment"
export { promptLine, promptSecret } from "./key-store"
export {
  buildRunEnv,
  injectTemplate,
  parseRef,
  parseVaultCoordinate,
} from "./refs"
