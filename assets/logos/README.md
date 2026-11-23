# Official SentinelAI artwork

The twelve SVGs in this directory are unchanged source files. Use `SentinelAILogoFull.svg` on navy (`#03094B`) and `SentinelAILogoTotal-NoBG(Orange).svg` on maroon (`#541504`). The matching compact marks are `SentinelAILogoIcon(Purple).svg` and `SentinelAILogoIcon(Orange).svg`.

The compact purple mark is the default macOS application icon and Chrome toolbar icon. To regenerate both apps' raster assets, install the dependencies in `mac-app/`, then run `node assets/logos/build-icons.mjs` from the repository root. The generator centers the official SVG on each theme color at its original aspect ratio.
