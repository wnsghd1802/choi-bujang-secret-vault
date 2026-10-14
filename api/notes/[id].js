import { withDeviceGate } from '../../src/device-security.mjs';
import { createNotesHandler } from '../../src/notes-api.mjs';
export default withDeviceGate(createNotesHandler({ item: true }));