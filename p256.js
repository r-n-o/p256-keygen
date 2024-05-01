// Converts an ArrayBuffer to a hex-encoded string
var buf2hex = function (buffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
};

// Takes a base64url-encoded string (e.g. "nMueRPiAm51YXEjRtka8S_8Ura3HaqbmqDqMJCZmvkM")
// and return the corresponding bytes, as an array buffer.
var base64urlDecode = function (s) {
  // Go from base64url encoding to base64 encoding
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  // use `atob` to decode base64
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};

// Accepts a public key array buffer, and returns a buffer with the compressed version of the public key
function compressRawPublicKey(rawPublicKey) {
  const rawPublicKeyBytes = new Uint8Array(rawPublicKey);
  const len = rawPublicKeyBytes.byteLength;

  // Drop the y coordinate
  var compressedBytes = rawPublicKeyBytes.slice(0, (1 + len) >>> 1);

  // Encode the parity of `y` in first bit
  compressedBytes[0] = 0x2 | (rawPublicKeyBytes[len - 1] & 0x01);
  return compressedBytes.buffer;
}

var p256Keygen = async function () {
  // Create a new P-256 keypair
  const p256Keypair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  );

  // Export the raw public key. By default this will export in uncompressed format
  const rawPublicKey = await crypto.subtle.exportKey(
    "raw",
    p256Keypair.publicKey
  );

  // We need to export with JWK format because exporting EC private keys with "raw" isn't supported
  const privateKeyJwk = await crypto.subtle.exportKey(
    "jwk",
    p256Keypair.privateKey
  );

  // Optional: compress the public key! But you don't have to
  const compressedPublicKeyBuffer = compressRawPublicKey(rawPublicKey);

  const privateKeyBuffer = base64urlDecode(privateKeyJwk.d);
  return {
    public: buf2hex(compressedPublicKeyBuffer),
    public_uncompressed: buf2hex(rawPublicKey),
    private: buf2hex(privateKeyBuffer),
  };
};

document.getElementById("keygen").addEventListener("click", function () {
  p256Keygen()
    .then(function (keypair) {
      console.log("New keypair", keypair);
      document.getElementById("public-key").value = keypair.public;
      document.getElementById("public-key-uncompressed").value =
        keypair.public_uncompressed;
      document.getElementById("private-key").value = keypair.private;
    })
    .catch(console.error);
});
