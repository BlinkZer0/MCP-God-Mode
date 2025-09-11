// Image Editor - React Application
const { useState, useEffect, useRef } = React;

function ImageEditor() {
    const [sessions, setSessions] = useState([]);
    const [activeSession, setActiveSession] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    
    const fileInputRef = useRef(null);

    // API call function
    const apiCall = async (endpoint, data = {}) => {
        try {
            const response = await fetch(`/api/image/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            return await response.json();
        } catch (error) {
            setError(error.message);
            throw error;
        }
    };

    // Open image
    const openImage = async (file) => {
        setIsLoading(true);
        try {
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch('/api/image/upload', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                const session = await apiCall('open', {
                    source: result.path,
                    sessionName: file.name
                });
                
                setSessions(prev => [...prev, session]);
                setActiveSession(session);
            }
        } catch (error) {
            setError('Failed to open image: ' + error.message);
        } finally {
            setIsLoading(false);
        }
    };

    // Apply operation
    const applyOperation = async (operation, params) => {
        if (!activeSession) return;
        
        try {
            await apiCall('edit', {
                sessionId: activeSession.sessionId,
                op: operation,
                params: params
            });
        } catch (error) {
            setError('Failed to apply operation: ' + error.message);
        }
    };

    // Export image
    const exportImage = async () => {
        if (!activeSession) return;
        
        try {
            const result = await apiCall('export', {
                sessionId: activeSession.sessionId,
                format: 'png',
                quality: 90
            });
            
            if (result.ok) {
                console.log('Image exported:', result.path);
            }
        } catch (error) {
            setError('Failed to export image: ' + error.message);
        }
    };

    // File handling
    const handleFileSelect = (e) => {
        const file = e.target.files[0];
        if (file) {
            openImage(file);
        }
    };

    return (
        <div className="image-editor">
            <header className="editor-header">
                <h1>Image Editor</h1>
                <button 
                    className="btn btn-primary"
                    onClick={() => fileInputRef.current?.click()}
                >
                    Open Image
                </button>
                <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/*"
                    onChange={handleFileSelect}
                    style={{ display: 'none' }}
                />
                <button 
                    className="btn btn-secondary"
                    onClick={exportImage}
                    disabled={!activeSession}
                >
                    Export
                </button>
            </header>

            <div className="editor-content">
                <aside className="sidebar">
                    <div className="sidebar-section">
                        <h3>Sessions</h3>
                        <div className="session-list">
                            {sessions.map(session => (
                                <div 
                                    key={session.id}
                                    className={`session-item ${activeSession?.id === session.id ? 'active' : ''}`}
                                    onClick={() => setActiveSession(session)}
                                >
                                    <div className="session-name">{session.name}</div>
                                    <div className="session-info">
                                        {session.dimensions && (
                                            <span>{session.dimensions.width}×{session.dimensions.height}</span>
                                        )}
                                        {session.format && (
                                            <span className="format">{session.format.toUpperCase()}</span>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="sidebar-section">
                        <h3>Adjustments</h3>
                        <AdjustmentPanel onApply={applyOperation} />
                    </div>

                    <div className="sidebar-section">
                        <h3>Filters</h3>
                        <FilterPanel onApply={applyOperation} />
                    </div>
                </aside>

                <main className="canvas-area">
                    <div className="canvas-container">
                        {!activeSession ? (
                            <div className="empty-state">
                                <h2>No Image Loaded</h2>
                                <p>Click "Open Image" to get started</p>
                            </div>
                        ) : (
                            <div className="image-preview">
                                <h3>{activeSession.name}</h3>
                                <p>Dimensions: {activeSession.dimensions?.width}×{activeSession.dimensions?.height}</p>
                                <p>Format: {activeSession.format}</p>
                            </div>
                        )}
                    </div>
                </main>
            </div>

            {isLoading && (
                <div className="loading-overlay">
                    <div className="spinner"></div>
                    <p>Processing...</p>
                </div>
            )}

            {error && (
                <div className="error-toast">
                    <span>{error}</span>
                    <button onClick={() => setError(null)}>×</button>
                </div>
            )}
        </div>
    );
}

// Adjustment Panel Component
function AdjustmentPanel({ onApply }) {
    const [brightness, setBrightness] = useState(1);
    const [saturation, setSaturation] = useState(1);

    const handleApply = () => {
        onApply('enhance', {
            brightness: brightness,
            saturation: saturation
        });
    };

    return (
        <div className="adjustment-panel">
            <div className="slider-group">
                <label>Brightness</label>
                <input
                    type="range"
                    min="0"
                    max="2"
                    step="0.1"
                    value={brightness}
                    onChange={(e) => setBrightness(parseFloat(e.target.value))}
                />
                <span>{brightness.toFixed(1)}</span>
            </div>
            
            <div className="slider-group">
                <label>Saturation</label>
                <input
                    type="range"
                    min="0"
                    max="2"
                    step="0.1"
                    value={saturation}
                    onChange={(e) => setSaturation(parseFloat(e.target.value))}
                />
                <span>{saturation.toFixed(1)}</span>
            </div>
            
            <button className="btn btn-primary btn-full" onClick={handleApply}>
                Apply Adjustments
            </button>
        </div>
    );
}

// Filter Panel Component
function FilterPanel({ onApply }) {
    const filters = [
        { name: 'Grayscale', type: 'grayscale' },
        { name: 'Sepia', type: 'sepia' },
        { name: 'Blur', type: 'blur', params: { radius: 1 } },
        { name: 'Sharpen', type: 'sharpen', params: { sigma: 1 } }
    ];

    return (
        <div className="filter-panel">
            {filters.map(filter => (
                <button
                    key={filter.type}
                    className="filter-btn"
                    onClick={() => onApply('filter', { type: filter.type, ...filter.params })}
                >
                    {filter.name}
                </button>
            ))}
        </div>
    );
}

// Initialize Lucide icons
document.addEventListener('DOMContentLoaded', () => {
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
});

// Render the application
ReactDOM.render(<ImageEditor />, document.getElementById('root'));