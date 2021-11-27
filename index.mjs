
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

/**
 * NIST SP800-108 KDF Counter implementation 
 * See section 5.1 in https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
 * @param sizeBytes   - Required size of the output
 * @param hashAlg     - Hashing algorithm for HMac
 * @param key         - HMac Key
 * @param label       - KDF label string. E.g. FDO uses "FDO-KDF" as label
 * @param context     - KDF context string. E.g. FDO uses "AutomaticOnboardTunnel" as TO2
 * @param contextRand - Context additional random bytes
 * @returns 
 */
export function CounterKDF(sizeBytes, hashAlg, key, label, context, contextRand) {
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
        mac.update(label);
        mac.update(Buffer.from([0]));
        mac.update(context);
        mac.update(contextRand);
        mac.update(Buffer.from([(l >> 8) & 0xff, l & 0xff]));

        resultBuffer = Buffer.concat([resultBuffer, mac.digest("buffer")])
    }

    return resultBuffer.slice(0, sizeBytes)
}
