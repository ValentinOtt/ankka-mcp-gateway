export const CUSTOMER_INSTALL_ROOT_PATH = '/__ankka/install' as const;
export const CUSTOMER_INSTALL_CONTINUE_PATH = '/__ankka/install/continue' as const;
export const CUSTOMER_INSTALL_OAUTH_START_PATH = '/__ankka/install/oauth/start' as const;
export const CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH = '/__ankka/install/oauth/callback' as const;
export const CUSTOMER_INSTALL_STATUS_PATH = '/__ankka/install/status' as const;
/**
 * Later operations (a source installation today) are authorized on the
 * gateway itself. The page under the root reads the dashboard's handoff
 * fragment; the callback stays the certified install callback.
 */
export const CUSTOMER_OPERATION_ROOT_PATH = '/__ankka/operation' as const;
export const CUSTOMER_OPERATION_OAUTH_START_PATH = '/__ankka/operation/oauth/start' as const;

