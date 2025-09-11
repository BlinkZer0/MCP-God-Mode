// Enhanced Multimedia Editor - Kdenlive 25.08.0 + Audacity 3.7.5 + GIMP 3.0.4 Integration
// React Application combining the latest features from these three applications

const { useState, useEffect, useRef, useCallback } = React;

function EnhancedMultimediaEditor() {
    // Enhanced State Management
    const [sessions, setSessions] = useState([]);
    const [projects, setProjects] = useState([]);
    const [activeSession, setActiveSession] = useState(null);
    const [activeProject, setActiveProject] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    
    // Enhanced UI State
    const [sidebarOpen, setSidebarOpen] = useState(true);
    const [currentView, setCurrentView] = useState('sessions');
    const [selectedMode, setSelectedMode] = useState('select');
    const [activePanel, setActivePanel] = useState('layers');
    const [workspaceLayout, setWorkspaceLayout] = useState('default');
    
    // Generation State
    const [generationPrompt, setGenerationPrompt] = useState('');
    const [generationType, setGenerationType] = useState('svg');
    const [generationStyle, setGenerationStyle] = useState('modern');
    const [generationSize, setGenerationSize] = useState({ width: 512, height: 512 });
    const [isGenerating, setIsGenerating] = useState(false);
    
    // Enhanced Audio State (Audacity 3.7.5 features)
    const [audioTracks, setAudioTracks] = useState([]);
    const [isRecording, setIsRecording] = useState(false);
    const [audioDevices, setAudioDevices] = useState([]);
    const [spectralView, setSpectralView] = useState(false);
    const [audioEffects, setAudioEffects] = useState([]);
    const [realTimeProcessing, setRealTimeProcessing] = useState(false);
    
    // Enhanced Image State (GIMP 3.0.4 features)
    const [imageLayers, setImageLayers] = useState([]);
    const [activeLayer, setActiveLayer] = useState(null);
    const [canvasSize, setCanvasSize] = useState({ width: 1920, height: 1080 });
    const [zoomLevel, setZoomLevel] = useState(100);
    const [colorSpace, setColorSpace] = useState('RGB');
    const [bitDepth, setBitDepth] = useState(8);
    const [nonDestructiveEditing, setNonDestructiveEditing] = useState(true);
    
    // Enhanced Video State (Kdenlive 25.08.0 features)
    const [videoTracks, setVideoTracks] = useState([]);
    const [timelinePosition, setTimelinePosition] = useState(0);
    const [playbackSpeed, setPlaybackSpeed] = useState(1);
    const [isPlaying, setIsPlaying] = useState(false);
    const [videoEffects, setVideoEffects] = useState([]);
    const [keyframes, setKeyframes] = useState([]);
    const [proxyMode, setProxyMode] = useState(false);
    
    // Enhanced Refs
    const fileInputRef = useRef(null);
    const canvasRef = useRef(null);
    const audioRef = useRef(null);
    const videoRef = useRef(null);
    const wavesurferRef = useRef(null);
    const fabricCanvasRef = useRef(null);
    const konvaStageRef = useRef(null);
    const ffmpegRef = useRef(null);

    // Enhanced API call function with error handling
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

    // Enhanced Audio Processing (Audacity 3.7.5 features)
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

    // Enhanced Image Processing (GIMP 3.0.4 features)
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

    // Enhanced Video Processing (Kdenlive 25.08.0 features)
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

    // Enhanced file handling with drag & drop
    const handleFileSelect = (e) => {
        const files = Array.from(e.target.files);
        files.forEach(file => openMedia(file));
    };

    const handleDrop = useCallback((e) => {
        e.preventDefault();
        const files = Array.from(e.dataTransfer.files);
        files.forEach(file => openMedia(file));
    }, []);

    const handleDragOver = useCallback((e) => {
        e.preventDefault();
    }, []);

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

    // Generation Functions
    const generateContent = async (type, prompt, options = {}) => {
        setIsGenerating(true);
        setError(null);
        
        try {
            const result = await apiCall(`generate_${type}`, {
                prompt: prompt,
                width: options.width || generationSize.width,
                height: options.height || generationSize.height,
                style: options.style || generationStyle,
                model: options.model || 'stable-diffusion',
                quality: options.quality || 80,
                outputFormat: options.outputFormat || (type === 'svg' ? 'svg' : 'png')
            });
            
            if (result.success) {
                // Create a new session for the generated content
                const session = {
                    id: result.sessionId,
                    name: `Generated ${type.toUpperCase()}: ${prompt.substring(0, 30)}...`,
                    type: 'image',
                    layers: 1,
                    createdAt: new Date().toISOString(),
                    modifiedAt: new Date().toISOString()
                };
                
                setSessions(prev => [...prev, session]);
                setActiveSession(session);
                setCurrentView('editor');
                setGenerationPrompt('');
            }
        } catch (error) {
            setError('Failed to generate content: ' + error.message);
        } finally {
            setIsGenerating(false);
        }
    };

    const handleGenerateSVG = () => {
        if (generationPrompt.trim()) {
            generateContent('svg', generationPrompt, {
                style: generationStyle,
                width: generationSize.width,
                height: generationSize.height
            });
        }
    };

    const handleGenerateBitmap = () => {
        if (generationPrompt.trim()) {
            generateContent('bitmap', generationPrompt, {
                style: generationStyle,
                width: generationSize.width,
                height: generationSize.height
            });
        }
    };

    const handleGenerateAIImage = () => {
        if (generationPrompt.trim()) {
            generateContent('ai_image', generationPrompt, {
                style: generationStyle,
                width: generationSize.width,
                height: generationSize.height
            });
        }
    };

    // Load status on mount
    useEffect(() => {
        loadStatus();
    }, []);

    return (
        <div 
            className="enhanced-multimedia-editor"
            onDrop={handleDrop}
            onDragOver={handleDragOver}
        >
            {/* Enhanced Header */}
            <header className="editor-header">
                <div className="header-left">
                    <button 
                        className="menu-toggle"
                        onClick={() => setSidebarOpen(!sidebarOpen)}
                    >
                        <i data-lucide="menu"></i>
                    </button>
                    <h1>Enhanced Multimedia Editor</h1>
                    <div className="app-badges">
                        <span className="badge kdenlive">🎬 Kdenlive 25.08.0</span>
                        <span className="badge audacity">🎵 Audacity 3.7.5</span>
                        <span className="badge gimp">🖼️ GIMP 3.0.4</span>
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
                        multiple
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
                {/* Enhanced Sidebar */}
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
                                    Audio (Audacity 3.7.5)
                                </button>
                                <button 
                                    className={`mode-btn ${selectedMode === 'image' ? 'active' : ''}`}
                                    onClick={() => setSelectedMode('image')}
                                >
                                    <i data-lucide="image"></i>
                                    Image (GIMP 3.0.4)
                                </button>
                                <button 
                                    className={`mode-btn ${selectedMode === 'video' ? 'active' : ''}`}
                                    onClick={() => setSelectedMode('video')}
                                >
                                    <i data-lucide="video"></i>
                                    Video (Kdenlive 25.08.0)
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
                                <button 
                                    className={`panel-btn ${activePanel === 'generate' ? 'active' : ''}`}
                                    onClick={() => setActivePanel('generate')}
                                >
                                    <i data-lucide="wand-2"></i>
                                    Generate
                                </button>
                            </div>
                        </div>

                        {/* Active Panel Content */}
                        {activePanel === 'layers' && (
                            <EnhancedLayersPanel 
                                session={activeSession}
                                onManageLayers={manageLayers}
                            />
                        )}

                        {activePanel === 'timeline' && (
                            <EnhancedTimelinePanel 
                                session={activeSession}
                                onManageTimeline={manageTimeline}
                            />
                        )}

                        {activePanel === 'effects' && (
                            <EnhancedEffectsPanel 
                                mode={selectedMode}
                                onProcessAudio={processAudio}
                                onProcessImage={processImage}
                                onProcessVideo={processVideo}
                            />
                        )}

                        {activePanel === 'tools' && (
                            <EnhancedToolsPanel 
                                mode={selectedMode}
                                session={activeSession}
                            />
                        )}

                        {activePanel === 'generate' && (
                            <GenerationPanel 
                                prompt={generationPrompt}
                                setPrompt={setGenerationPrompt}
                                type={generationType}
                                setType={setGenerationType}
                                style={generationStyle}
                                setStyle={setGenerationStyle}
                                size={generationSize}
                                setSize={setGenerationSize}
                                isGenerating={isGenerating}
                                onGenerateSVG={handleGenerateSVG}
                                onGenerateBitmap={handleGenerateBitmap}
                                onGenerateAIImage={handleGenerateAIImage}
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
                        <EnhancedSessionsView 
                            sessions={sessions}
                            onSessionSelect={(session) => {
                                setActiveSession(session);
                                setCurrentView('editor');
                            }}
                            onFileSelect={() => fileInputRef.current?.click()}
                        />
                    )}

                    {currentView === 'projects' && (
                        <EnhancedProjectsView 
                            projects={projects}
                            onProjectSelect={setActiveProject}
                        />
                    )}

                    {currentView === 'editor' && (
                        <EnhancedEditorView 
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

// Enhanced Layers Panel Component (GIMP 3.0.4 features)
function EnhancedLayersPanel({ session, onManageLayers }) {
    const [newLayerName, setNewLayerName] = useState('');
    const [layerType, setLayerType] = useState('image_layer');

    const addLayer = () => {
        if (newLayerName.trim()) {
            onManageLayers('add_layer', { 
                name: newLayerName,
                type: layerType,
                nonDestructive: true
            });
            setNewLayerName('');
        }
    };

    return (
        <div className="layers-panel">
            <div className="panel-header">
                <h4>Layers (GIMP 3.0.4)</h4>
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
                <select
                    value={layerType}
                    onChange={(e) => setLayerType(e.target.value)}
                    className="layer-type-select"
                >
                    <option value="image_layer">Image Layer</option>
                    <option value="text_layer">Text Layer</option>
                    <option value="adjustment_layer">Adjustment Layer</option>
                    <option value="effect_layer">Effect Layer</option>
                </select>
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
                            <span className="layer-type-badge">{layer.type}</span>
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
                                <option value="color_dodge">Color Dodge</option>
                                <option value="color_burn">Color Burn</option>
                                <option value="darken">Darken</option>
                                <option value="lighten">Lighten</option>
                                <option value="difference">Difference</option>
                                <option value="exclusion">Exclusion</option>
                            </select>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

// Enhanced Timeline Panel Component (Kdenlive 25.08.0 features)
function EnhancedTimelinePanel({ session, onManageTimeline }) {
    const [newTrackName, setNewTrackName] = useState('');
    const [trackType, setTrackType] = useState('video');

    const addTrack = () => {
        if (newTrackName.trim()) {
            onManageTimeline('add_track', { 
                name: newTrackName, 
                type: trackType,
                proxyMode: false
            });
            setNewTrackName('');
        }
    };

    return (
        <div className="timeline-panel">
            <div className="panel-header">
                <h4>Timeline (Kdenlive 25.08.0)</h4>
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
                <select
                    value={trackType}
                    onChange={(e) => setTrackType(e.target.value)}
                    className="track-type-select"
                >
                    <option value="video">Video Track</option>
                    <option value="audio">Audio Track</option>
                    <option value="subtitle">Subtitle Track</option>
                </select>
            </div>

            <div className="timeline-tracks">
                {session?.timeline?.tracks?.map(track => (
                    <div key={track.id} className="timeline-track">
                        <div className="track-header">
                            <span className="track-name">{track.name}</span>
                            <span className="track-type">{track.type}</span>
                            {track.proxyMode && <span className="proxy-indicator">Proxy</span>}
                        </div>
                        <div className="track-clips">
                            {track.clips.map(clip => (
                                <div key={clip.id} className="timeline-clip">
                                    <span className="clip-duration">
                                        {clip.start}s - {clip.end}s
                                    </span>
                                    {clip.effects.length > 0 && (
                                        <span className="effects-indicator">
                                            {clip.effects.length} effects
                                        </span>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

// Enhanced Effects Panel Component
function EnhancedEffectsPanel({ mode, onProcessAudio, onProcessImage, onProcessVideo }) {
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

    // Enhanced Audio Effects (Audacity 3.7.5)
    const audioEffects = [
        { name: 'amplify', label: 'Amplify', params: ['gainDb'] },
        { name: 'reverb', label: 'Reverb', params: ['roomSize', 'damping'] },
        { name: 'echo', label: 'Echo', params: ['delay', 'decay'] },
        { name: 'fade_in', label: 'Fade In', params: ['duration'] },
        { name: 'fade_out', label: 'Fade Out', params: ['duration'] },
        { name: 'normalize', label: 'Normalize', params: [] },
        { name: 'noise_reduction', label: 'Noise Reduction', params: ['sensitivity'] },
        { name: 'spectral_analysis', label: 'Spectral Analysis', params: [] }
    ];

    // Enhanced Image Effects (GIMP 3.0.4)
    const imageEffects = [
        { name: 'brightness_contrast', label: 'Brightness/Contrast', params: ['brightness', 'contrast'] },
        { name: 'hue_saturation', label: 'Hue/Saturation', params: ['hue', 'saturation'] },
        { name: 'gaussian_blur', label: 'Gaussian Blur', params: ['radius'] },
        { name: 'sharpen', label: 'Sharpen', params: ['amount'] },
        { name: 'emboss', label: 'Emboss', params: ['angle', 'height'] },
        { name: 'oil_paint', label: 'Oil Paint', params: ['brushSize', 'coarseness'] },
        { name: 'lens_distortion', label: 'Lens Distortion', params: ['strength'] },
        { name: 'perspective', label: 'Perspective', params: ['angle'] }
    ];

    // Enhanced Video Effects (Kdenlive 25.08.0)
    const videoEffects = [
        { name: 'color_correction', label: 'Color Correction', params: ['brightness', 'contrast', 'saturation'] },
        { name: 'speed_change', label: 'Speed Change', params: ['speed'] },
        { name: 'fade_in', label: 'Fade In', params: ['duration'] },
        { name: 'fade_out', label: 'Fade Out', params: ['duration'] },
        { name: 'blur', label: 'Blur', params: ['radius'] },
        { name: 'chroma_key', label: 'Chroma Key', params: ['color', 'tolerance'] },
        { name: 'stabilization', label: 'Stabilization', params: ['strength'] },
        { name: 'proxy_mode', label: 'Proxy Mode', params: ['quality'] }
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

// Enhanced Tools Panel Component
function EnhancedToolsPanel({ mode, session }) {
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
                        <button className="tool-btn">
                            <i data-lucide="bar-chart-3"></i>
                            Spectral
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="volume-2"></i>
                            Normalize
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
                        <button className="tool-btn">
                            <i data-lucide="type"></i>
                            Text
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="layers"></i>
                            Layers
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
                        <button className="tool-btn">
                            <i data-lucide="zap"></i>
                            Effects
                        </button>
                        <button className="tool-btn">
                            <i data-lucide="key"></i>
                            Keyframes
                        </button>
                    </>
                )}
            </div>
        </div>
    );
}

// Enhanced Sessions View Component
function EnhancedSessionsView({ sessions, onSessionSelect, onFileSelect }) {
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

// Enhanced Projects View Component
function EnhancedProjectsView({ projects, onProjectSelect }) {
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

// Enhanced Editor View Component
function EnhancedEditorView({ session, mode, onProcessAudio, onProcessImage, onProcessVideo }) {
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

// Generation Panel Component
function GenerationPanel({ 
    prompt, setPrompt, type, setType, style, setStyle, size, setSize, 
    isGenerating, onGenerateSVG, onGenerateBitmap, onGenerateAIImage 
}) {
    return (
        <div className="generation-panel">
            <div className="panel-header">
                <h4>Content Generation</h4>
            </div>

            <div className="generation-controls">
                <div className="input-group">
                    <label>Prompt:</label>
                    <textarea
                        value={prompt}
                        onChange={(e) => setPrompt(e.target.value)}
                        placeholder="Describe what you want to generate..."
                        className="prompt-input"
                        rows="3"
                    />
                </div>

                <div className="input-group">
                    <label>Type:</label>
                    <select
                        value={type}
                        onChange={(e) => setType(e.target.value)}
                        className="type-select"
                    >
                        <option value="svg">SVG Graphics</option>
                        <option value="bitmap">Bitmap Image</option>
                        <option value="ai_image">AI Image</option>
                    </select>
                </div>

                <div className="input-group">
                    <label>Style:</label>
                    <select
                        value={style}
                        onChange={(e) => setStyle(e.target.value)}
                        className="style-select"
                    >
                        <option value="modern">Modern</option>
                        <option value="realistic">Realistic</option>
                        <option value="abstract">Abstract</option>
                        <option value="minimalist">Minimalist</option>
                    </select>
                </div>

                <div className="size-controls">
                    <label>Size:</label>
                    <div className="size-inputs">
                        <input
                            type="number"
                            value={size.width}
                            onChange={(e) => setSize(prev => ({ ...prev, width: parseInt(e.target.value) || 512 }))}
                            placeholder="Width"
                            className="size-input"
                            min="1"
                            max="8192"
                        />
                        <span>×</span>
                        <input
                            type="number"
                            value={size.height}
                            onChange={(e) => setSize(prev => ({ ...prev, height: parseInt(e.target.value) || 512 }))}
                            placeholder="Height"
                            className="size-input"
                            min="1"
                            max="8192"
                        />
                    </div>
                </div>

                <div className="generation-buttons">
                    <button 
                        className="btn btn-primary"
                        onClick={onGenerateSVG}
                        disabled={!prompt.trim() || isGenerating}
                    >
                        <i data-lucide="wand-2"></i>
                        Generate SVG
                    </button>
                    
                    <button 
                        className="btn btn-secondary"
                        onClick={onGenerateBitmap}
                        disabled={!prompt.trim() || isGenerating}
                    >
                        <i data-lucide="image"></i>
                        Generate Bitmap
                    </button>
                    
                    <button 
                        className="btn btn-accent"
                        onClick={onGenerateAIImage}
                        disabled={!prompt.trim() || isGenerating}
                    >
                        <i data-lucide="sparkles"></i>
                        Generate AI Image
                    </button>
                </div>

                {isGenerating && (
                    <div className="generation-status">
                        <div className="spinner"></div>
                        <span>Generating content...</span>
                    </div>
                )}
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
ReactDOM.render(<EnhancedMultimediaEditor />, document.getElementById('root'));
