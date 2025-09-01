"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ChartJSNodeCanvasBase = void 0;
const path_1 = require("path");
const freshRequire_1 = require("./freshRequire");
const backgroundColourPlugin_1 = require("./backgroundColourPlugin");
class ChartJSNodeCanvasBase {
    /**
     * Create a new instance of CanvasRenderService.
     *
     * @param options Configuration for this instance
     */
    constructor(options) {
        if (options === null || typeof (options) !== 'object') {
            throw new Error('An options parameter object is required');
        }
        if (!options.width || typeof (options.width) !== 'number') {
            throw new Error('A width option is required');
        }
        if (!options.height || typeof (options.height) !== 'number') {
            throw new Error('A height option is required');
        }
        this._width = options.width;
        this._height = options.height;
        const canvas = (0, freshRequire_1.freshRequire)('canvas');
        this._createCanvas = canvas.createCanvas;
        this._registerFont = canvas.registerFont;
        this._image = canvas.Image;
        this._type = options.type && options.type.toLowerCase();
        this._chartJs = this.initialize(options);
    }
    /**
     * Use to register the font with Canvas to use a font file that is not installed as a system font, this must be done before the Canvas is created.
     *
     * @param path The path to the font file.
     * @param options The font options.
     * @example
     * registerFont('comicsans.ttf', { family: 'Comic Sans' });
     */
    registerFont(path, options) {
        this._registerFont(path, options);
    }
    initialize(options) {
        var _a, _b, _c, _d;
        const chartJs = require('chart.js/auto');
        if ((_a = options.plugins) === null || _a === void 0 ? void 0 : _a.requireChartJSLegacy) {
            for (const plugin of options.plugins.requireChartJSLegacy) {
                require(plugin);
                delete require.cache[require.resolve(plugin)];
            }
        }
        if ((_b = options.plugins) === null || _b === void 0 ? void 0 : _b.globalVariableLegacy) {
            global.Chart = chartJs;
            for (const plugin of options.plugins.globalVariableLegacy) {
                (0, freshRequire_1.freshRequire)(plugin);
            }
            delete global.Chart;
        }
        if ((_c = options.plugins) === null || _c === void 0 ? void 0 : _c.modern) {
            for (const plugin of options.plugins.modern) {
                if (typeof plugin === 'string') {
                    chartJs.register((0, freshRequire_1.freshRequire)(plugin));
                }
                else {
                    chartJs.register(plugin);
                }
            }
        }
        if ((_d = options.plugins) === null || _d === void 0 ? void 0 : _d.requireLegacy) {
            for (const plugin of options.plugins.requireLegacy) {
                chartJs.register((0, freshRequire_1.freshRequire)(plugin));
            }
        }
        if (options.chartCallback) {
            options.chartCallback(chartJs);
        }
        if (options.backgroundColour) {
            chartJs.register(new backgroundColourPlugin_1.BackgroundColourPlugin(options.width, options.height, options.backgroundColour));
        }
        const chartJsPath = (0, path_1.join)('node_modules', 'chart.js');
        for (const key of Object.keys(require.cache)) {
            if (key.includes(chartJsPath)) {
                delete require.cache[key];
            }
        }
        return chartJs;
    }
}
exports.ChartJSNodeCanvasBase = ChartJSNodeCanvasBase;
//# sourceMappingURL=chartJSNodeCanvasBase.js.map