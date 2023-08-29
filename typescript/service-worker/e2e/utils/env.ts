const getEnvVar = (varName: string): string => {
  if (!process.env[varName]) {
    throw new Error(`${varName} is not set`);
  }

  return process.env[varName];
};

export const env = {
  baseUrl: getEnvVar('BASE_URL'),
  swPath: getEnvVar('SW_PATH'),
  currentSwPath: getEnvVar('CURRENT_SW_PATH'),
  latestSwPath: getEnvVar('LATEST_SW_PATH'),
  previousSwPath: getEnvVar('PREVIOUS_SW_PATH'),
  brokenUpgradeSwPath: getEnvVar('BROKEN_UPGRADE_SW_PATH'),
  brokenDowngradeSwPath: getEnvVar('BROKEN_DOWNGRADE_SW_PATH'),
};
