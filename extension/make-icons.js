const sharp = require("sharp");

const logos = [
    { src: "public/logos/SentinelAILogoIconOnlySentinel(Purple).svg", prefix: "purple_minimal", density: 300 },
    { src: "public/logos/SentinelAILogoIcon-SentinelOnly(Orange).svg", prefix: "orange_minimal", density: 300 },
    { src: "public/logos/SentinelAILogoIcon(Purple).svg", prefix: "purple_emblem", density: 96 },
    { src: "public/logos/SentinelAILogoIcon(Orange).svg", prefix: "orange_emblem", density: 96 }
];

(async () => {
    for (const { src, prefix, density } of logos) {
        const image = await sharp(src, { density })
            .trim()
            .png()
            .toBuffer();

        for (const size of [16, 32, 48, 128]) {
            await sharp(image)
                .resize(size, size, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 } })
                .png()
                .toFile(`public/logos/${prefix}_${size}.png`);
        }
    }
    console.log("Done!");
})();