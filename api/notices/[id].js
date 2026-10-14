import { withDeviceGate } from '../../src/device-security.mjs';
import { createNoticeHandler } from '../../src/notices-api.mjs';
export default withDeviceGate(createNoticeHandler());