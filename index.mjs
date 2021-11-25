
const { createHmac } = await import('crypto');

const HashInfo = {
    "sha256": {
        "lenBits": 256
    },
    "sha384": {
        "lenBits": 384
    }
}

const FDO_KDF_LABEL   = Buffer.from("FIDO-KDF", "utf-8");
const FDO_KDF_CONTEXT = Buffer.from("AutomaticOnboardTunnel", "utf-8");

// Implementation of SP800-108 section 5.1 KDF in Counter Mode
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
export function CounterKDF(sizeBytes, hashAlg, key, contextRand) {
    const hInfo = HashInfo[hashAlg];

    if (!hInfo) {
        throw new Error(`"${hashAlg}" is an unknown hash algorithm!`);
    }

    if (!contextRand) {
        contextRand = Buffer.alloc(0);
    }

    const h = hInfo.lenBits;
    const l = sizeBytes * 8;

    const n = Math.ceil(l / h);

    let resultBuffer = Buffer.alloc(0);

    for (let i = 0; i < n; i++) {
        const mac = createHmac(hashAlg, key);

        mac.update(Buffer.from([i]));
        mac.update(FDO_KDF_LABEL);
        mac.update(Buffer.from([0]));
        mac.update(FDO_KDF_CONTEXT);
        mac.update(contextRand);
        mac.update(Buffer.from([(l >> 8) & 0xff, l & 0xff]));

        resultBuffer = Buffer.concat([resultBuffer, mac.digest("buffer")])
    }

    return resultBuffer.slice(0, sizeBytes)
}