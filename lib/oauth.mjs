import { GoogleProvider } from './providers/google.mjs';

// Public compatibility facade: constructor options, mutable test/operator
// configuration, lifecycle methods, callback URL and errors remain unchanged.
export class GoogleOAuthManager extends GoogleProvider {}
