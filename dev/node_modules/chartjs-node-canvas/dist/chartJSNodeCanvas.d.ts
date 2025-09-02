import { Readable } from 'stream';
import { ChartConfiguration } from 'chart.js/auto';
import { ChartJSNodeCanvasBase, MimeType } from './chartJSNodeCanvasBase';
export declare class ChartJSNodeCanvas extends ChartJSNodeCanvasBase {
    /**
     * Render to a data url.
     * @see https://github.com/Automattic/node-canvas#canvastodataurl
     *
     * @param configuration The Chart JS configuration for the chart to render.
     * @param mimeType The image format, `image/png` or `image/jpeg`.
     */
    renderToDataURL(configuration: ChartConfiguration, mimeType?: MimeType): Promise<string>;
    /**
     * Render to a data url synchronously.
     * @see https://github.com/Automattic/node-canvas#canvastodataurl
     *
     * @param configuration The Chart JS configuration for the chart to render.
     * @param mimeType The image format, `image/png` or `image/jpeg`.
     */
    renderToDataURLSync(configuration: ChartConfiguration, mimeType?: MimeType): string;
    /**
     * Render to a buffer.
     * @see https://github.com/Automattic/node-canvas#canvastobuffer
     *
     * @param configuration The Chart JS configuration for the chart to render.
     * @param mimeType A string indicating the image format. Valid options are `image/png`, `image/jpeg` (if node-canvas was built with JPEG support) or `raw` (unencoded ARGB32 data in native-endian byte order, top-to-bottom). Defaults to `image/png` for image canvases, or the corresponding type for PDF or SVG canvas.
     */
    renderToBuffer(configuration: ChartConfiguration, mimeType?: MimeType): Promise<Buffer>;
    /**
     * Render to a buffer synchronously.
     * @see https://github.com/Automattic/node-canvas#canvastobuffer
     *
     * @param configuration The Chart JS configuration for the chart to render.
     * @param mimeType A string indicating the image format. Valid options are `image/png`, `image/jpeg` (if node-canvas was built with JPEG support), `raw` (unencoded ARGB32 data in native-endian byte order, top-to-bottom), `application/pdf` (for PDF canvases) and image/svg+xml (for SVG canvases). Defaults to `image/png` for image canvases, or the corresponding type for PDF or SVG canvas.
     */
    renderToBufferSync(configuration: ChartConfiguration, mimeType?: MimeType | 'application/pdf' | 'image/svg+xml'): Buffer;
    /**
     * Render to a stream.
     * @see https://github.com/Automattic/node-canvas#canvascreatepngstream
     *
     * @param configuration The Chart JS configuration for the chart to render.
     * @param mimeType A string indicating the image format. Valid options are `image/png`, `image/jpeg` (if node-canvas was built with JPEG support), `application/pdf` (for PDF canvases) and image/svg+xml (for SVG canvases). Defaults to `image/png` for image canvases, or the corresponding type for PDF or SVG canvas.
     */
    renderToStream(configuration: ChartConfiguration, mimeType?: MimeType | 'application/pdf'): Readable;
    private renderChart;
}
