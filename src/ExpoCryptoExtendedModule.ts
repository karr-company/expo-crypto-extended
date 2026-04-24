import { NativeModule, requireNativeModule } from 'expo';

import { ExpoCryptoExtendedModuleEvents } from './ExpoCryptoExtended.types';

declare class ExpoCryptoExtendedModule extends NativeModule<ExpoCryptoExtendedModuleEvents> {
  PI: number;
  hello(): string;
  setValueAsync(value: string): Promise<void>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ExpoCryptoExtendedModule>('ExpoCryptoExtended');
