/**
 * HTTP configuration side effects.
 *
 * This module configures axios defaults (used by @did-plc/lib).
 * Import this module for side effects before making any HTTP requests.
 */

import axios from 'axios';
import { userAgent, timeout } from './utils.js';

axios.defaults.headers.common['User-Agent'] = userAgent;
axios.defaults.timeout = timeout;
