import {
  parseAuthenticatorData,
  parseAttestationObject,
  parseClientDataJSON,
} from "./output-parser";

import coseToJwk from "cose-to-jwk";

export function binToHex(data) {
  if (!(data instanceof Buffer)) {
    try {
      data = Buffer.from(data);
    } catch (e) {
      return "";
    }
  }

  return data.toString("hex");
}

export function hexToBin(data) {
  return Buffer.from(data, "hex");
}

export function binToString(data) {
  if (!(data instanceof Buffer)) {
    try {
      data = Buffer.from(data);
    } catch (e) {
      return "";
    }
  }

  return data.toString("binary");
}

export default function convertAAGUIDToString(aaguid) {
  // Raw Hex: adce000235bcc60a648b0b25f1f05503
  const hex = aaguid.toString("hex");

  const segments = [
    hex.slice(0, 8), // 8
    hex.slice(8, 12), // 4
    hex.slice(12, 16), // 4
    hex.slice(16, 20), // 4
    hex.slice(20, 32), // 8
  ];

  // Formatted: adce0002-35bc-c60a-648b-0b25f1f05503
  return segments.join("-");
}

export const prettifyTransformations = {
  rawId: {
    transform: binToHex,
    buttons: ["Use", "Download"],
  },
  sig: {
    transform: binToHex,
    buttons: ["Download"],
  },
  signature: {
    transform: binToHex,
    buttons: ["Download"],
  },
  userHandle: {
    transform: binToHex,
    buttons: ["Download"],
  },
  x5c: {
    transform: (arr) => arr.map(binToHex),
    buttons: ["View", "Download PEM"],
  },
  credentialPublicKey: {
    transform: coseToJwk,
    buttons: ["Download COSE", "Download JWK", "Download PEM"],
  },
  authenticatorData: {
    transform: parseAuthenticatorData,
  },
  attestationObject: {
    transform: parseAttestationObject,
  },
  clientDataJSON: {
    transform: parseClientDataJSON,
  },
  aaguid: {
    transform: convertAAGUIDToString,
  },
  credentialId: {
    transform: binToHex,
  },
};

export const binToHexTransformations = {
  rawId: {
    transform: binToHex,
    buttons: ["Use", "Download"],
  },
  sig: {
    transform: binToHex,
    buttons: ["Download"],
  },
  signature: {
    transform: binToHex,
    buttons: ["Download"],
  },
  userHandle: {
    transform: binToHex,
    buttons: ["Download"],
  },
  x5c: {
    transform: (arr) => arr.map(binToHex),
    buttons: ["View", "Download PEM"],
  },
  credentialPublicKey: {
    transform: coseToBinHex,
    buttons: ["Download COSE", "Download JWK", "Download PEM"],
  },
  authenticatorData: {
    transform: binToHex,
  },
  attestationObject: {
    transform: binToHex,
  },
  clientDataJSON: {
    transform: binToHex,
  },
  aaguid: {
    transform: binToHex,
  },
  credentialId: {
    transform: binToHex,
  },
};

export const hexToBinTransformations = {
  rawId: {
    transform: hexToBin,
    buttons: ["Use", "Download"],
  },
  sig: {
    transform: hexToBin,
    buttons: ["Download"],
  },
  signature: {
    transform: hexToBin,
    buttons: ["Download"],
  },
  userHandle: {
    transform: hexToBin,
    buttons: ["Download"],
  },
  x5c: {
    transform: (arr) => arr.map(hexToBin),
    buttons: ["View", "Download PEM"],
  },
  credentialPublicKey: {
    transform: hexToBin,
    buttons: ["Download COSE", "Download JWK", "Download PEM"],
  },
  authenticatorData: {
    transform: hexToBin,
  },
  attestationObject: {
    transform: hexToBin,
  },
  clientDataJSON: {
    transform: hexToBin,
  },
  aaguid: {
    transform: hexToBin,
  },
  credentialId: {
    transform: hexToBin,
  },
};

function coseToBinHex(cose) {
  if (typeof cose !== "object") {
    throw new TypeError(
      "'cose' argument must be an object, probably an Buffer conatining valid COSE"
    );
  }

  // convert Uint8Array, etc. to ArrayBuffer
  if (cose.buffer instanceof ArrayBuffer && !(cose instanceof Buffer)) {
    cose = cose.buffer;
  }

  if (Array.isArray(cose)) {
    cose = Buffer.from(cose);
  }

  // convert ArrayBuffer to Buffer
  if (cose instanceof ArrayBuffer) {
    cose = Buffer.from(new Uint8Array(cose));
  }

  if (!(cose instanceof Buffer)) {
    throw new TypeError("could not convert 'cose' argument to a Buffer");
  }

  if (cose.length < 3) {
    throw new RangeError("COSE buffer was too short: " + cose.length);
  }

  return cose.toString("hex");
}
