import java.awt.AlphaComposite;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.nio.file.Path;
import javax.imageio.ImageIO;

class MeowzIconDensity {
    public static void main(String[] args) throws Exception {
        if (args.length > 1 || (args.length == 1 && !args[0].equals("--write"))) {
            throw new IllegalArgumentException("Run from the repository root. Pass --write to regenerate the launcher icons.");
        }
        boolean write = args.length == 1;
        var source = ImageIO.read(Path.of("docs/icon.png").toFile());
        var base = Path.of("mobile/src/main/res");
        var densities = new String[]{"mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"};
        var scales = new double[]{1, 1.5, 2, 3, 4};
        for (int i = 0; i < densities.length; ++i) {
            var dir = base.resolve("mipmap-" + densities[i]);
            int size = (int)(48 * scales[i]);
            int layer = (int)(108 * scales[i]);
            int artwork = (int)(74 * scales[i]);
            var legacy = dir.resolve("ic_launcher.png");
            var adaptive = dir.resolve("ic_launcher_foreground.png");
            if (write) {
                render(source, size, size, legacy);
                render(source, layer, artwork, adaptive);
            }
            verify(legacy, adaptive, size, layer);
        }
    }
    private static void verify(Path legacyFile, Path adaptiveFile, int legacySize, int size) throws Exception {
        var legacy = ImageIO.read(legacyFile.toFile());
        var adaptive = ImageIO.read(adaptiveFile.toFile());
        if (legacy.getWidth() != legacySize || legacy.getHeight() != legacySize ||
                (legacy.getRGB(0, 0) >>> 24) != 0 || adaptive.getWidth() != size || adaptive.getHeight() != size) {
            throw new IllegalStateException("Wrong dimensions or transparent corners in " + adaptiveFile);
        }
        double mid = size / 2.0;
        double radius = size * 33.0 / 108;
        int yellow = 0;
        for (int y = (int)(size * 0.64); y < (int)(size * 0.80); ++y) {
            for (int x = (int)(size * 0.42); x < (int)(size * 0.58); ++x) {
                int c = adaptive.getRGB(x, y);
                if ((c >>> 24) >= 224 && ((c >>> 16) & 255) > 175 &&
                        ((c >>> 8) & 255) > 105 && (c & 255) < 90) {
                    ++yellow;
                    double dx = x + 0.5 - mid;
                    double dy = y + 0.5 - mid;
                    if (dx * dx + dy * dy > radius * radius) {
                        throw new IllegalStateException("Z exceeds the circular safe area in " + adaptiveFile);
                    }
                }
            }
        }
        if (yellow <= size * size / 200) {
            throw new IllegalStateException("Missing yellow Z in " + adaptiveFile);
        }
    }
    private static void render(BufferedImage source, int grid, int artwork, Path file) throws Exception {
        var canvas = new BufferedImage(grid, grid, BufferedImage.TYPE_INT_ARGB);
        var g = canvas.createGraphics();
        g.setComposite(AlphaComposite.Src);
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
        g.drawImage(source, (grid-artwork)/2, (grid-artwork)/2, artwork, artwork, null);
        g.dispose();
        ImageIO.write(canvas, "png", file.toFile());
    }
}
