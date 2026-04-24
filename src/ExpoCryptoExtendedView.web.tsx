import * as React from 'react';

import { ExpoCryptoExtendedViewProps } from './ExpoCryptoExtended.types';

export default function ExpoCryptoExtendedView(props: ExpoCryptoExtendedViewProps) {
  return (
    <div>
      <iframe
        style={{ flex: 1 }}
        src={props.url}
        onLoad={() => props.onLoad({ nativeEvent: { url: props.url } })}
      />
    </div>
  );
}
