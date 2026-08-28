import { REVIEWED_GATEWAY_DEPLOY_ACTIVATION } from './reviewed-activation';
import { createReviewedGatewayDeployEntrypoint } from './reviewed-runtime';

// This entrypoint is buildable for review, but the exact compile-time
// activation is false/null. It therefore constructs only the fixed zero-write
// health/unavailable shell, without reading environment bindings.
export default createReviewedGatewayDeployEntrypoint(REVIEWED_GATEWAY_DEPLOY_ACTIVATION);
