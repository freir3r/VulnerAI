// ShodanApi.js - Helper for Shodan API queries
// Usage: require('./ShodanApi')(apiKey)

const fetch = require('node-fetch');

// Replace with your Shodan API key
const SHODAN_API_KEY = process.env.SHODAN_API_KEY || 'gJYVZ7FDskOVqqZeuVfHwJIGNz7hzZaH';

/**
 * Get host information from Shodan (open ports, banners, CVEs, etc.)
 * @param {string} ip - The IP address to query
 * @returns {Promise<object>} - Shodan host info JSON
 */
async function getHostInfo(ip, apiKey = SHODAN_API_KEY) {
  const url = `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Shodan API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

// Example usage:
// (async () => {
//   try {
//     const data = await getHostInfo('8.8.8.8');
//     console.log(JSON.stringify(data, null, 2));
//   } catch (err) {
//     console.error(err);
//   }
// })();

module.exports = { getHostInfo };
/*
  Copyright Jesús Rubio <jesusprubio@gmail.com>

  This code may only be used under the MIT license found at
  https://opensource.org/licenses/MIT.
*/

/* eslint-disable no-console */

'use strict';

const util = require('util');

const client = require('../');

const apiKey = 'YOURKEYHERE';

client.streams
  .banners(apiKey)
  .then(res => {
    console.log('Result:');
    console.log(util.inspect(res, { depth: 6 }));
  })
  .catch(err => {
    console.log('Error:');
    console.log(err);
  });

// client.streams.asn('3303,32475', apiKey)
// .then(res => {
//   console.log('Result:');
//   console.log(util.inspect(res, { depth: 6 }));
// })
// .catch(err => {
//   console.log('Error:');
//   console.log(err);
// });

// client.streams.countries('DE,US', apiKey)
// .then(res => {
//   console.log('Result:');
//   console.log(util.inspect(res, { depth: 6 }));
// })
// .catch(err => {
//   console.log('Error:');
//   console.log(err);
// });
//
// client.streams.ports('1434,27017,6379', apiKey)
// .then(res => {
//   console.log('Result:');
//   console.log(util.inspect(res, { depth: 6 }));
// })
// .catch(err => {
//   console.log('Error:');
//   console.log(err);
// });