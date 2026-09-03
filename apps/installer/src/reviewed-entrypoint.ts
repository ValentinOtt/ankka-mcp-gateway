import { REVIEWED_GATEWAY_DEPLOY_ACTIVATION } from './reviewed-activation';
import { createTwoStageDeployEntrypoint } from './two-stage-runtime';

// The Wrangler main module for deploy.ankka.ai. It is buildable for review,
// but the exact compile-time activation is false/null, so it constructs only
// the fixed zero-write health/unavailable shell and reads no binding. The
// clean two-stage runtime is the only mutation entrypoint behind it; the
// legacy installer route graph is not reachable from here.
export { TwoStageDeploySession } from './two-stage-deploy-session';
export default createTwoStageDeployEntrypoint(REVIEWED_GATEWAY_DEPLOY_ACTIVATION);
