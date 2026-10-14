import { withDeviceGate } from '../src/device-security.mjs';
import { createRecoveryHandler } from '../src/recovery-api.mjs';
export default withDeviceGate(createRecoveryHandler());