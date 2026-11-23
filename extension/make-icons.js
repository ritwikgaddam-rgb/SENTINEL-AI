const sharp = require("sharp");

const logos = [
    ["public/logos/SentinelAILogoIconOnlySentinel(Purple).svg", "purple_minimal"],
    ["public/logos/SentinelAILogoIcon-SentinelOnly(Orange).svg", "orange_minimal"]
];

(async () => {
    for (const [src, prefix] of logos) {
        for (const size of [16, 32, 48, 128]) {
            await sharp(src, { density: 300 })
                .trim()
                .resize(size, size, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 } })
                .png()
                .toFile(`public/logos/${prefix}_${size}.png`);
        }
    }
    console.log("Done!");
})();