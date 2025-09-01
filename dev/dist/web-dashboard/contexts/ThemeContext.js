"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useTheme = exports.ThemeContext = void 0;
const react_1 = require("react");
exports.ThemeContext = (0, react_1.createContext)(undefined);
const useTheme = () => {
    const context = (0, react_1.useContext)(exports.ThemeContext);
    if (context === undefined) {
        throw new Error('useTheme must be used within a ThemeProvider');
    }
    return context;
};
exports.useTheme = useTheme;
