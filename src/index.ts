// Reexport the native module. On web, it will be resolved to ExpoCryptoExtendedModule.web.ts
// and on native platforms to ExpoCryptoExtendedModule.ts
export { default } from './ExpoCryptoExtendedModule';
export { default as ExpoCryptoExtendedView } from './ExpoCryptoExtendedView';
export * from  './ExpoCryptoExtended.types';
