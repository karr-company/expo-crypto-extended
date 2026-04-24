import { requireNativeView } from 'expo';
import * as React from 'react';

import { ExpoCryptoExtendedViewProps } from './ExpoCryptoExtended.types';

const NativeView: React.ComponentType<ExpoCryptoExtendedViewProps> =
  requireNativeView('ExpoCryptoExtended');

export default function ExpoCryptoExtendedView(props: ExpoCryptoExtendedViewProps) {
  return <NativeView {...props} />;
}
