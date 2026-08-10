export {
  api,
  apiOptional,
  completeRecovery,
  doctorE2ee,
  downloadFile,
  fetchGithubOidcToken,
  getConfig,
  getConfigForVltOwner,
  rawApi,
  rawSecretsApi,
  resolveItem,
  resolveVault,
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
  type VaultConfig,
} from "./e2ee-client"
export { encodeBase64 } from "./e2ee-crypto"
export { promptSecret } from "./key-store"
export {
  buildRunEnv,
  injectTemplate,
  parseRef,
  parseVaultCoordinate,
} from "./refs"
