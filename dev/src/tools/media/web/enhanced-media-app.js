// Enhanced Media Editor - Kdenlive + Audacity + GIMP Conglomerate
// React Application combining the best features of these three applications

const { useState, useEffect, useRef } = React;

function EnhancedMediaEditor() {
    // State Management
    const [sessions, setSessions] = useState([]);
    const [projects, setProjects] = useState([]);
    const [activeSession, setActiveSession] = useState(null);
    const [activeProject, setActiveProject] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    
    // UI State
    const [sidebarOpen, setSidebarOpen] = useState(true);
    const [currentView, setCurrentView] = useState('sessions'); // sessions, projects, editor
    const [selectedMode, setSelectedMode] = useState('select'); // select, audio, image, video
    const [activePanel, setActivePanel] = useState('layers'); // layers, timeline, effects, tools
    
    // Audio State (Audacity-inspired)
    const [audioTracks, setAudioTracks] = useState([]);
    const [isRecording, setIsRecording] = useState(false);
    const [audioDevices, setAudioDevices] = useState([]);
    const [spectralView, setSpectralView] = useState(false);
    
    // Image State (GIMP-inspired)
    const [imageLayers, setImageLayers] = useState([]);
    const [activeLayer, setActiveLayer] = useState(null);
    const [canvasSize, setCanvasSize] = useState({ width: 1920, height: 1080 });
    const [zoomLevel, setZoomLevel] = useState(100);
    
    // Video State (Kdenlive-inspired)
    const [videoTracks, setVideoTracks] = useState([]);
    const [timelinePosition, setTimelinePosition] = useState(0);
    const [playbackSpeed, setPlaybackSpeed] = useState(1);
    const [isPlaying, setIsPlaying] = useState(false);
    
    // Refs
    const fileInputRef = useRef(null);
    const canvasRef = useRef(null);
    const audioRef = useRef(null);
    const videoRef = useRef(null);
    const wavesurferRef = useRef(null);
    const fabricCanvasRef = useRef(null);

    // API call function
    const apiCall = async (endpoint, data = {}) => {
        try {
            const response = await fetch(`/api/enhanced_media_editor/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            
            if (!response.ok) {
                throw new Error(`API call failed: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            setError(error.message);
            throw error;
        }
    };

    // Load status
    const loadStatus = async () => {
        try {
            const result = await apiCall('status');
            setSessions(result.sessions || []);
            setProjects(result.projects || []);
        } catch (error) {
            console.error('Failed to load status:', error);
        }
    };

    // Audio Processing (Audacity-style)
    const processAudio = async (operation, params, trackId = null) => {
        if (!activeSession) return;
        
        try {
            const result = await apiCall('process_audio', {
                sessionId: activeSession.id,
                operation: operation,
                params: params,
                trackId: trackId
            });
            
            if (result.success) {
                console.log('Audio operation applied:', operation);
                await loadStatus();
            }
        } catch (error) {
            setError('Failed to apply audio operation: ' + error.message);
        }
    };

    // Image Processing (GIMP-style)
    const processImage = async (operation, params, layerId = null) => {
        if (!activeSession) return;
        
        try {
            const result = await apiCall('process_image', {
                sessionId: activeSession.id,
                operation: operation,
                params: params,
                layerId: layerId
            });
            
            if (result.success) {
                console.log('Image operation applied:', operation);
                await loadStatus();
            }
        } catch (error) {
            setError('Failed to apply image operation: ' + error.message);
        }
    };

    // Video Processing (Kdenlive-style)
    const processVideo = async (operation, params, trackId = null, clipId = null) => {
        if (!activeSession) return;
        
        try {
            const result = await apiCall('process_video', {
                sessionId: activeSession.id,
                operation: operation,
                params: params,
                trackId: trackId,
                clipId: clipId
            });
            
            if (result.success) {
                console.log('Video operation applied:', operation);
                await loadStatus();
            }
        } catch (error) {
            setError('Failed to apply video operation: ' + error.message);
        }
    };

    // Timeline Management (Kdenlive-style)
    const manageTimeline = async (action, trackData = null, clipData = null) => {
        if (!activeSession) return;
        
        try {
            const result = await apiCall('manage_timeline', {
                sessionId: activeSession.id,
                action: action,
                trackData: trackData,
                clipData: clipData
            });
            
            if (result.success) {
                console.log('Timeline operation completed:', action);
                await loadStatus();
            }
        } catch (error) {
            setError('Failed to manage timeline: ' + error.message);
        }
    };

    // Layer Management (GIMP-style)
    const manageLayers = async (action, layerData = null) => {
        if (!activeSession) return;
        
        try {
            const result = await apiCall('manage_layers', {
                sessionId: activeSession.id,
                action: action,
                layerData: layerData
            });
            
            if (result.success) {
                console.log('Layer operation completed:', action);
                await loadStatus();
            }
        } catch (error) {
            setError('Failed to manage layers: ' + error.message);
        }
    };

    // File handling
    const handleFileSelect = (e) => {
        const file = e.target.files[0];
        if (file) {
            openMedia(file);
        }
    };

    const openMedia = async (file) => {
        setIsLoading(true);
        setError(null);
        
        try {
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch('/api/enhanced_media_editor/upload', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                const session = await apiCall('create_session', {
                    source: result.path,
                    sessionName: file.name,
                    type: detectMediaType(file)
                });
                
                setSessions(prev => [...prev, session]);
                setActiveSession(session);
                setCurrentView('editor');
            }
        } catch (error) {
            setError('Failed to open media: ' + error.message);
        } finally {
            setIsLoading(false);
        }
    };

    const detectMediaType = (file) => {
        const type = file.type;
        if (type.startsWith('audio/')) return 'audio';
        if (type.startsWith('image/')) return 'image';
        if (type.startsWith('video/')) return 'video';
        return 'mixed';
    };

    // Load status on mount
    useEffect(() => {
        loadStatus();
    }, []);

    return (
        <div className="enhanced-media-editor">
            {/* Header */}
            <header className="editor-header">
                <div className="header-left">
                    <button 
                        className="menu-toggle"
                        onClick={() => setSidebarOpen(!sidebarOpen)}
                    >
                        <i data-lucide="menu"></i>
                    </button>
                    <h1>Enhanced Media Editor</h1>
                    <div className="app-badges">
                        <span className="badge kdenlive">🎬 Kdenlive</span>
                        <span className="badge audacity">🎵 Audacity</span>
                        <span className="badge gimp">🖼️ GIMP</span>
                    </div>
                </div>
                
                <div className="header-center">
                    <div className="view-tabs">
                        <button 
                            className={`tab-btn ${currentView === 'sessions' ? 'active' : ''}`}
                            onClick={() => setCurrentView('sessions')}
                        >
                            <i data-lucide="folder"></i>
                            Sessions
                        </button>
                        <button 
                            className={`tab-btn ${currentView === 'projects' ? 'active' : ''}`}
                            onClick={() => setCurrentView('projects')}
                        >
                            <i data-lucide="folder-open"></i>
                            Projects
                        </button>
                        <button 
                            className={`tab-btn ${currentView === 'editor' ? 'active' : ''}`}
                            onClick={() => setCurrentView('editor')}
                        >
                            <i data-lucide="edit"></i>
                            Editor
                        </button>
                    </div>
                </div>
                
                <div className="header-right">
                    <button 
                        className="btn btn-primary"
                        onClick={() => fileInputRef.current?.click()}
                    >
                        <i data-lucide="upload"></i>
                        Open Media
                    </button>
                    <input
                        ref={fileInputRef}
                        type="file"
                        accept="audio/*,image/*,video/*"
                        onChange={handleFileSelect}
                        style={{ display: 'none' }}
                    />
                    
                    <button 
                        className="btn btn-secondary"
                        onClick={() => exportMedia()}
                        disabled={!activeSession}
                    >
                        <i data-lucide="download"></i>
                        Export
                    </button>
                </div>
            </header>

            <div className="editor-content">
                {/* Sidebar */}
                {sidebarOpen && (
                    <aside className="editor-sidebar">
                        {/* Mode Selection */}
                        <div className="sidebar-section">
                            <h3>Editing Mode</h3>
                            <div className="mode-buttons">
                                <button 
                                    className={`mode-btn ${selectedMode === 'audio' ? 'active' : ''}`}
                                    onClick={() => setSelectedMode('audio')}
                                >
                                    <i data-lucide="music"></i>
                                    Audio (Audacity)
                                </button>
                                <button 
                                    className={`mode-btn ${selectedMode === 'image' ? 'active' : ''}`}
                                    onClick={() => setSelectedMode('image')}
                                >
                                    <i data-lucide="image"></i>
                                    Image (GIMP)
                                </button>
                                <button 
                                    className={`mode-btn ${selectedMode === 'video' ? 'active' : ''}`}
                                    onClick={() => setSelectedMode('video')}
                                >
                                    <i data-lucide="video"></i>
                                    Video (Kdenlive)
                                </button>
                            </div>
                        </div>

                        {/* Panel Selection */}
                        <div className="sidebar-section">
                            <h3>Panels</h3>
                            <div className="panel-buttons">
                                <button 
                                    className={`panel-btn ${activePanel === 'layers' ? 'active' : ''}`}
                                    onClick={() => setActivePanel('layers')}
                                >
                                    <i data-lucide="layers"></i>
                                    Layers
                                </button>
                                <button 
                                    className={`panel-btn ${activePanel === 'timeline' ? 'active' : ''}`}
                                    onClick={() => setActivePanel('timeline')}
                                >
                                    <i data-lucide="clock"></i>
                                    Timeline
                                </button>
                                <button 
                                    className={`panel-btn ${activePanel === 'effects' ? 'active' : ''}`}
                                    onClick={() => setActivePanel('effects')}
                                >
                                    <i data-lucide="sparkles"></i>
                                    Effects
                                </button>
                                <button 
                                    className={`panel-btn ${activePanel === 'tools' ? 'active' : ''}`}
                                    onClick={() => setActivePanel('tools')}
                                >
                                    <i data-lucide="wrench"></i>
                                    Tools
                                </button>
                            </div>
                        </div>

                        {/* Active Panel Content */}
                        {activePanel === 'layers' && (
                            <LayersPanel 
                                session={activeSession}
                                onManageLayers={manageLayers}
                            />
                        )}

                        {activePanel === 'timeline' && (
                            <TimelinePanel 
                                session={activeSession}
                                onManageTimeline={manageTimeline}
                            />
                        )}

                        {activePanel === 'effects' && (
                            <EffectsPanel 
                                mode={selectedMode}
                                onProcessAudio={processAudio}
                                onProcessImage={processImage}
                                onProcessVideo={processVideo}
                            />
                        )}

                        {activePanel === 'tools' && (
                            <ToolsPanel 
                                mode={selectedMode}
                                session={activeSession}
                            />
                        )}

                        {/* Sessions List */}
                        {currentView === 'sessions' && (
                            <div className="sidebar-section">
                                <h3>Sessions ({sessions.length})</h3>
                                <div className="session-list">
                                    {sessions.map(session => (
                                        <div 
                                            key={session.id}
                                            className={`session-item ${activeSession?.id === session.id ? 'active' : ''}`}
                                            onClick={() => {
                                                setActiveSession(session);
                                                setCurrentView('editor');
                                            }}
                                        >
                                            <div className="session-header">
                                                <i data-lucide={session.type === 'audio' ? 'music' : session.type === 'image' ? 'image' : 'video'}></i>
                                                <span className="session-name">{session.name}</span>
                                            </div>
                                            <div className="session-info">
                                                <span className="session-type">{session.type.toUpperCase()}</span>
                                                <span className="session-layers">{session.layers} layers</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </aside>
                )}

                {/* Main Content Area */}
                <main className="editor-main">
                    {currentView === 'sessions' && (
                        <SessionsView 
                            sessions={sessions}
                            onSessionSelect={(session) => {
                                setActiveSession(session);
                                setCurrentView('editor');
                            }}
                            onFileSelect={() => fileInputRef.current?.click()}
                        />
                    )}

                    {currentView === 'projects' && (
                        <ProjectsView 
                            projects={projects}
                            onProjectSelect={setActiveProject}
                        />
                    )}

                    {currentView === 'editor' && (
                        <EditorView 
                            session={activeSession}
                            mode={selectedMode}
                            onProcessAudio={processAudio}
                            onProcessImage={processImage}
                            onProcessVideo={processVideo}
                        />
                    )}
                </main>
            </div>

            {/* Loading Overlay */}
            {isLoading && (
                <div className="loading-overlay">
                    <div className="spinner"></div>
                    <p>Processing...</p>
                </div>
            )}

            {/* Error Display */}
            {error && (
                <div className="error-toast">
                    <i data-lucide="alert-circle"></i>
                    <span>{error}</span>
                    <button onClick={() => setError(null)}>
                        <i data-lucide="x"></i>
                    </button>
                </div>
            )}
        </div>
    );
}

// Layers Panel Component (GIMP-style)
function LayersPanel({ session, onManageLayers }) {
    const [newLayerName, setNewLayerName] = useState('');

    const addLayer = () => {
        if (newLayerName.trim()) {
            onManageLayers('add_layer', { name: newLayerName });
            setNewLayerName('');
        }
    };

    return (
        <div className="layers-panel">
            <div className="panel-header">
                <h4>Layers</h4>
                <button 
                    className="btn btn-sm btn-primary"
                    onClick={addLayer}
                >
                    <i data-lucide="plus"></i>
                </button>
            </div>
            
            <div className="layer-controls">
                <input
                    type="text"
                    value={newLayerName}
                    onChange={(e) => setNewLayerName(e.target.value)}
                    placeholder="New layer name"
                    className="layer-name-input"
                />
            </div>

            <div className="layers-list">
                {session?.layers?.map(layer => (
                    <div key={layer.id} className="layer-item">
                        <div className="layer-header">
                            <input
                                type="checkbox"
                                checked={layer.visible}
                                onChange={() => onManageLayers('set_layer_properties', {
                                    layerId: layer.id,
                                    visible: !layer.visible
                                })}
                            />
                            <span className="layer-name">{layer.name}</span>
                        </div>
                        <div className="layer-controls">
                            <input
                                type="range"
                                min="0"
                                max="1"
                                step="0.01"
                                value={layer.opacity}
                                onChange={(e) => onManageLayers('set_layer_properties', {
                                    layerId: layer.id,
                                    opacity: parseFloat(e.target.value)
                                })}
                                className="opacity-slider"
                            />
                            <select
                                value={layer.blendMode}
                                onChange={(e) => onManageLayers('set_layer_properties', {
                                    layerId: layer.id,
                                    blendMode: e.target.value
                                })}
                                className="blend-mode-select"
                            >
                                <option value="normal">Normal</option>
                                <option value="multiply">Multiply</option>
                                <option value="screen">Screen</option>
                                <option value="overlay">Overlay</option>
                                <option value="soft_light">Soft Light</option>
                                <option value="hard_light">Hard Light</option>
                            </select>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

// Timeline Panel Component (Kdenlive-style)
function TimelinePanel({ session, onManageTimeline }) {
    const [newTrackName, setNewTrackName] = useState('');

    const addTrack = () => {
        if (newTrackName.trim()) {
            onManageTimeline('add_track', { name: newTrackName, type: 'video' });
            setNewTrackName('');
        }
    };

    return (
        <div className="timeline-panel">
            <div className="panel-header">
                <h4>Timeline</h4>
                <button 
                    className="btn btn-sm btn-primary"
                    onClick={addTrack}
                >
                    <i data-lucide="plus"></i>
                </button>
            </div>

            <div className="track-controls">
                <input
                    type="text"
                    value={newTrackName}
                    onChange={(e) => setNewTrackName(e.target.value)}
                    placeholder="New track name"
                    className="track-name-input"
                />
            </div>

            <div className="timeline-tracks">
                {session?.timeline?.tracks?.map(track => (
                    <div key={track.id} className="timeline-track">
                        <div className="track-header">
                            <span className="track-name">{track.name}</span>
                            <span className="track-type">{track.type}</span>
                        </div>
                        <div className="track-clips">
                            {track.clips.map(clip => (
                                <div key={clip.id} className="timeline-clip">
                                    <span className="clip-duration">
                                        {clip.start}s - {clip.end}s
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

// Effects Panel Component
function EffectsPanel({ mode, onProcessAudio, onProcessImage, onProcessVideo }) {
    const [effectParams, setEffectParams] = useState({});

    const applyEffect = (operation, params) => {
        switch (mode) {
            case 'audio':
                onProcessAudio(operation, params);
                break;
            case 'image':
                onProcessImage(operation, params);
                break;
            case 'video':
                onProcessVideo(operation, params);
                break;
        }
    };

    const audioEffects = [
        { name: 'amplify', label: 'Amplify', params: ['gainDb'] },
        { name: 'reverb', label: 'Reverb', params: ['roomSize', 'damping'] },
        { name: 'echo', label: 'Echo', params: ['delay', 'decay'] },
        { name: 'fade_in', label: 'Fade In', params: ['duration'] },
        { name: 'fade_out', label: 'Fade Out', params: ['duration'] },
        { name: 'normalize', label: 'Normalize', params: [] }
    ];

    const imageEffects = [
        { name: 'brightness_contrast', label: 'Brightness/Contrast', params: ['brightness', 'contrast'] },
        { name: 'hue_saturation', label: 'Hue/Saturation', params: ['hue', 'saturation'] },
        { name: 'gaussian_blur', label: 'Gaussian Blur', params: ['radius'] },
        { name: 'sharpen', label: 'Sharpen', params: ['amount'] },
        { name: 'emboss', label: 'Emboss', params: ['angle', 'height'] },
        { name: 'oil_paint', label: 'Oil Paint', params: ['brushSize', 'coarseness'] }
    ];

    const videoEffects = [
        { name: 'color_correction', label: 'Color Correction', params: ['brightness', 'contrast', 'saturation'] },
        { name: 'speed_change', label: 'Speed Change', params: ['speed'] },
        { name: 'fade_in', label: 'Fade In', params: ['duration'] },
        { name: 'fade_out', label: 'Fade Out', params: ['duration'] },
        { name: 'blur', label: 'Blur', params: ['radius'] },
        { name: 'chroma_key', label: 'Chroma Key', params: ['color', 'tolerance'] }
    ];

    const currentEffects = mode === 'audio' ? audioEffects : mode === 'image' ? imageEffects : videoEffects;

    return (
        <div className="effects-panel">
            <div className="panel-header">
                <h4>Effects ({mode})</h4>
            </div>

            <div className="effects-list">
                {currentEffects.map(effect => (
                    <div key={effect.name} className="effect-item">
                        <div className="effect-header">
                            <span className="effect-name">{effect.label}</span>
                            <button 
                                className="btn btn-sm btn-primary"
                                onClick={() => applyEffect(effect.name, effectParams)}
                            >
                                Apply
                            </button>
                        </div>
                        
                        {effect.params.length > 0 && (
                            <div className="effect-params">
                                {effect.params.map(param => (
                                    <div key={param} className="param-group">
                                        <label>{param}:</label>
                                        <input
                                            type="number"
                                            value={effectParams[param] || 0}
                                            onChange={(e) => setEffectParams(prev => ({
                                                ...prev,
                                                [param]: parseFloat(e.target.value)
                                            }))}
                                            placeholder={param}
                                            className="param-input"
                                        />
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}

// Tools Panel Component
function ToolsPanel({ mode, session }) {
    return (
        <div className="tools-panel">
            <div className="panel-header">
                <h4>Tools ({mode})</h4>
            </div>

            <div className="tools-grid">
                {mode === 'audio' && (
                    <>
                        <button className="tool-btn">
                            <i data-lucide="mic"></i>
                            Record
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="scissors"></i>
                            Cut
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="copy"></i>
                            Copy
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="clipboard"></i>
                            Paste
                        </button>
                    </>
                )}

                {mode === 'image' && (
                    <>
                        <button className="tool-btn">
                            <i data-lucide="crop"></i>
                            Crop
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="move"></i>
                            Move
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="paintbrush"></i>
                            Brush
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="droplets"></i>
                            Fill
                        </button>
                    </>
                )}

                {mode === 'video' && (
                    <>
                        <button className="tool-btn">
                            <i data-lucide="play"></i>
                            Play
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="scissors"></i>
                            Cut
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="move"></i>
                            Move
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="plus"></i>
                            Add Clip
                        </button>
                    </>
                )}
            </div>
        </div>
    );
}

// Sessions View Component
function SessionsView({ sessions, onSessionSelect, onFileSelect }) {
    return (
        <div className="sessions-view">
            <div className="view-header">
                <h2>Media Sessions</h2>
                <p>Manage your active media editing sessions</p>
            </div>
            
            {sessions.length === 0 ? (
                <div className="empty-state">
                    <i data-lucide="folder-open" className="empty-icon"></i>
                    <h3>No Active Sessions</h3>
                    <p>Upload media files to start editing</p>
                    <button 
                        className="btn btn-primary"
                        onClick={onFileSelect}
                    >
                        <i data-lucide="upload"></i>
                        Open Media
                    </button>
                </div>
            ) : (
                <div className="sessions-grid">
                    {sessions.map(session => (
                        <div 
                            key={session.id}
                            className="session-card"
                            onClick={() => onSessionSelect(session)}
                        >
                            <div className="session-preview">
                                <i data-lucide={session.type === 'audio' ? 'music' : session.type === 'image' ? 'image' : 'video'}></i>
                            </div>
                            <div className="session-details">
                                <h4>{session.name}</h4>
                                <p>{session.type.toUpperCase()} • {session.layers} layers</p>
                                <p className="session-date">{new Date(session.modifiedAt).toLocaleDateString()}</p>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

// Projects View Component
function ProjectsView({ projects, onProjectSelect }) {
    return (
        <div className="projects-view">
            <div className="view-header">
                <h2>Projects</h2>
                <p>Organize your media sessions into projects</p>
            </div>
            
            {projects.length === 0 ? (
                <div className="empty-state">
                    <i data-lucide="folder-plus" className="empty-icon"></i>
                    <h3>No Projects</h3>
                    <p>Create a project to organize your media sessions</p>
                </div>
            ) : (
                <div className="projects-grid">
                    {projects.map(project => (
                        <div key={project.name} className="project-card">
                            <div className="project-header">
                                <h4>{project.name}</h4>
                                <span className="project-type-badge">{project.type}</span>
                            </div>
                            <div className="project-stats">
                                <span>{project.sessionCount} sessions</span>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

// Editor View Component
function EditorView({ session, mode, onProcessAudio, onProcessImage, onProcessVideo }) {
    if (!session) {
        return (
            <div className="empty-state">
                <i data-lucide="edit" className="empty-icon"></i>
                <h3>No Media Selected</h3>
                <p>Select a session from the sidebar or upload new media</p>
            </div>
        );
    }

    return (
        <div className="editor-workspace">
            <div className="editor-header">
                <h3>{session.name}</h3>
                <span className="session-type-badge">{session.type.toUpperCase()}</span>
                <span className="mode-badge">{mode.toUpperCase()} Mode</span>
            </div>
            
            <div className="media-preview">
                {session.type === 'image' && (
                    <div className="image-preview">
                        <canvas ref={fabricCanvasRef} className="fabric-canvas"></canvas>
                    </div>
                )}
                
                {session.type === 'audio' && (
                    <div className="audio-preview">
                        <div id="waveform" className="waveform-container"></div>
                        <audio 
                            ref={audioRef}
                            src={`/api/enhanced_media_editor/session/${session.id}`}
                            controls
                            className="audio-player"
                        />
                    </div>
                )}
                
                {session.type === 'video' && (
                    <div className="video-preview">
                        <video 
                            ref={videoRef}
                            src={`/api/enhanced_media_editor/session/${session.id}`}
                            controls
                            className="video-player"
                        />
                    </div>
                )}
            </div>
            
            <div className="editor-info">
                <div className="info-item">
                    <label>Type:</label>
                    <span>{session.type}</span>
                </div>
                <div className="info-item">
                    <label>Layers:</label>
                    <span>{session.layers}</span>
                </div>
                <div className="info-item">
                    <label>Modified:</label>
                    <span>{new Date(session.modifiedAt).toLocaleString()}</span>
                </div>
            </div>
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
ReactDOM.render(<EnhancedMediaEditor />, document.getElementById('root'));
