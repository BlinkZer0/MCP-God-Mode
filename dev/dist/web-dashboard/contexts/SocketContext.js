"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useSocket = exports.SocketContext = void 0;
const react_1 = require("react");
exports.SocketContext = (0, react_1.createContext)(undefined);
const useSocket = () => {
    const context = (0, react_1.useContext)(exports.SocketContext);
    if (context === undefined) {
        throw new Error('useSocket must be used within a SocketProvider');
    }
    return context;
};
exports.useSocket = useSocket;
