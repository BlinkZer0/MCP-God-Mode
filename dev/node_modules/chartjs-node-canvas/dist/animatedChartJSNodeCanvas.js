"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AnimatedChartJSNodeCanvas = void 0;
const chartJSNodeCanvasBase_1 = require("./chartJSNodeCanvasBase");
const animationFrameProvider = {
    cancelAnimationFrame: (handle) => clearImmediate(handle),
    requestAnimationFrame: (callback) => setImmediate(() => callback(Date.now())),
};
class AnimatedChartJSNodeCanvas extends chartJSNodeCanvasBase_1.ChartJSNodeCanvasBase {
    /**
     * Render to a data url array.
     * @see https://github.com/Automattic/node-canvas#canvastodataurl
     *
     * @param configuration The Chart JS configuration for the chart to render.
     * @param mimeType A string indicating the image format. Valid options are `image/png`, `image/jpeg` (if node-canvas was built with JPEG support), `raw` (unencoded ARGB32 data in native-endian byte order, top-to-bottom), `application/pdf` (for PDF canvases) and image/svg+xml (for SVG canvases). Defaults to `image/png` for image canvases, or the corresponding type for PDF or SVG canvas.
     */
    renderToDataURL(configuration, mimeType = 'image/png') {
        const frames = [];
        return new Promise((resolve, _reject) => {
            this.renderChart(configuration, (chart) => {
                const canvas = chart.canvas;
                if (!canvas) {
                    throw new Error('Canvas is null');
                }
                const dataUrl = canvas.toDataURL(mimeType);
                frames.push(dataUrl);
            }, (chart) => {
                resolve(frames);
                chart.destroy();
            });
        });
    }
    /**
     * Render to a buffer.
     * @see https://github.com/Automattic/node-canvas#canvastobuffer
     *
     * @param configuration The Chart JS configuration for the chart to render.
     * @param mimeType A string indicating the image format. Valid options are `image/png`, `image/jpeg` (if node-canvas was built with JPEG support) or `raw` (unencoded ARGB32 data in native-endian byte order, top-to-bottom). Defaults to `image/png` for image canvases, or the corresponding type for PDF or SVG canvas.
     */
    renderToBuffer(configuration, mimeType = 'image/png') {
        return new Promise((resolve, _reject) => {
            const frames = [];
            this.renderChart(configuration, (chart) => {
                const canvas = chart.canvas;
                if (!canvas) {
                    throw new Error('Canvas is null');
                }
                const buffer = canvas.toBuffer(mimeType);
                frames.push(buffer);
            }, (chart) => {
                resolve(frames);
                chart.destroy();
            });
        });
    }
    renderChart(configuration, onProgress, onComplete) {
        const canvas = this._createCanvas(this._width, this._height, this._type);
        canvas.style = canvas.style || {};
        const options = Object.assign({}, configuration.options);
        options.responsive = false;
        const animation = options.animation || {};
        if (!animation.duration) {
            animation.duration = 1000;
        }
        const baseOnProgress = animation.onProgress;
        animation.onProgress = (event) => {
            const currentStep = event.currentStep; // type docs wrong?
            const initial = !!event.initial ? event.initial : false; // added around 3.2.x
            const progress = currentStep / event.numSteps;
            if (baseOnProgress) {
                //baseOnComplete(event.chart);
                baseOnProgress.call(animation, event);
            }
            onProgress(event.chart, progress, initial);
        };
        const baseOnComplete = animation.onProgress;
        animation.onComplete = (event) => {
            const initial = !!event.initial ? event.initial : false; // added around 3.2.x
            if (baseOnComplete) {
                //baseOnComplete(event.chart);
                baseOnComplete.call(animation, event);
            }
            onComplete(event.chart, initial);
        };
        const plugins = configuration.plugins || [];
        const configuredChartConfig = Object.assign(Object.assign({}, configuration), { options, plugins });
        global.window = global.window || {};
        global.window.requestAnimationFrame = animationFrameProvider.requestAnimationFrame;
        global.window.cancelAnimationFrame = animationFrameProvider.cancelAnimationFrame;
        const context = canvas.getContext('2d');
        global.Image = this._image; // Some plugins use this API
        const chart = new this._chartJs(context, configuredChartConfig);
        delete global.Image;
        return chart;
    }
}
exports.AnimatedChartJSNodeCanvas = AnimatedChartJSNodeCanvas;
//# sourceMappingURL=animatedChartJSNodeCanvas.js.map