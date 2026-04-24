import { registerWebModule, NativeModule } from 'expo';

import { ExpoCryptoExtendedModuleEvents } from './ExpoCryptoExtended.types';

class ExpoCryptoExtendedModule extends NativeModule<ExpoCryptoExtendedModuleEvents> {
  PI = Math.PI;
  async setValueAsync(value: string): Promise<void> {
    this.emit('onChange', { value });
  }
  hello() {
    return 'Hello world! 👋';
  }
}

export default registerWebModule(ExpoCryptoExtendedModule, 'ExpoCryptoExtendedModule');
