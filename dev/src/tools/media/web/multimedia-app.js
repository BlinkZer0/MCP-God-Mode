// Multimedia Tool - React Application
const { useState, useEffect, useRef } = React;

function MultimediaTool() {
    const [sessions, setSessions] = useState([]);
    const [projects, setProjects] = useState([]);
    const [activeSession, setActiveSession] = useState(null);
    const [activeProject, setActiveProject] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    const [sidebarOpen, setSidebarOpen] = useState(true);
    const [selectedTool, setSelectedTool] = useState('select');
    const [currentView, setCurrentView] = useState('sessions'); // sessions, projects, editor
    const [audioDevices, setAudioDevices] = useState([]);
    const [isRecording, setIsRecording] = useState(false);
    const [recordingSession, setRecordingSession] = useState(null);
    const [isGenerating, setIsGenerating] = useState(false);
    const [generationPrompt, setGenerationPrompt] = useState('');
    const [generationType, setGenerationType] = useState('svg');
    
    const fileInputRef = useRef(null);
    const canvasRef = useRef(null);
    const audioRef = useRef(null);
    const videoRef = useRef(null);
    const mediaRecorderRef = useRef(null);

    // API call function
    const apiCall = async (endpoint, data = {}) => {
        try {
            const response = await fetch(`/api/multimedia/${endpoint}`, {
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

    // Open media file
    const openMedia = async (file) => {
        setIsLoading(true);
        setError(null);
        
        try {
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch('/api/multimedia/upload', {
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
                setCurrentView('editor');
            }
        } catch (error) {
            setError('Failed to open media: ' + error.message);
        } finally {
            setIsLoading(false);
        }
    };

    // Apply operation
    const applyOperation = async (operation, params) => {
        if (!activeSession) return;
        
        try {
            const result = await apiCall('edit', {
                sessionId: activeSession.sessionId,
                operation: operation,
                params: params
            });
            
            if (result.success) {
                console.log('Operation applied:', operation);
                await loadStatus(); // Refresh sessions
            }
        } catch (error) {
            setError('Failed to apply operation: ' + error.message);
        }
    };

    // Export media
    const exportMedia = async (format, quality) => {
        if (!activeSession) return;
        
        try {
            const result = await apiCall('export', {
                sessionId: activeSession.sessionId,
                format: format,
                quality: quality
            });
            
            if (result.success) {
                console.log('Media exported:', result.path);
            }
        } catch (error) {
            setError('Failed to export media: ' + error.message);
        }
    };

    // Create project
    const createProject = async (name, type, sessionIds) => {
        try {
            const result = await apiCall('create_project', {
                name: name,
                type: type,
                sessions: sessionIds
            });
            
            if (result.success) {
                setProjects(prev => [...prev, result]);
            }
        } catch (error) {
            setError('Failed to create project: ' + error.message);
        }
    };

    // File handling
    const handleFileSelect = (e) => {
        const file = e.target.files[0];
        if (file) {
            openMedia(file);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            openMedia(files[0]);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
    };

    // Load audio devices
    const loadAudioDevices = async () => {
        try {
            const result = await apiCall('get_audio_devices');
            setAudioDevices(result.devices?.input || []);
        } catch (error) {
            console.error('Failed to load audio devices:', error);
        }
    };

    // Start recording
    const startRecording = async (deviceType = 'auto', duration = 30, format = 'wav', quality = 80) => {
        setIsLoading(true);
        setError(null);
        
        try {
            const result = await apiCall('start_recording', {
                deviceType,
                duration,
                format,
                quality,
                sessionName: `Recording_${new Date().toISOString().replace(/[:.]/g, '-')}`
            });
            
            if (result.success) {
                setIsRecording(true);
                setRecordingSession(result);
                
                // Wait for recording to complete
                setTimeout(async () => {
                    setIsRecording(false);
                    setRecordingSession(null);
                    await loadStatus(); // Refresh sessions
                }, duration * 1000);
            }
        } catch (error) {
            setError('Failed to start recording: ' + error.message);
        } finally {
            setIsLoading(false);
        }
    };

    // Record what's playing (stereo mix)
    const recordWhatsPlaying = async (duration = 30) => {
        await startRecording('stereo_mix', duration, 'wav', 80);
    };

    // Record microphone
    const recordMicrophone = async (duration = 30) => {
        await startRecording('microphone', duration, 'wav', 80);
    };

    // Generation Functions
    const generateSVG = async (prompt, width = 800, height = 600, style = 'minimal', colors = [], elements = []) => {
        setIsGenerating(true);
        try {
            const response = await fetch('/api/multimedia_tool', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'generate_svg',
                    prompt,
                    width,
                    height,
                    style,
                    colors,
                    elements
                })
            });
            
            const result = await response.json();
            if (result.structuredContent.success) {
                // Load the generated SVG into a new session
                await loadSessions();
                setCurrentView('sessions');
            } else {
                setError(result.structuredContent.message);
            }
        } catch (error) {
            setError(`SVG generation failed: ${error.message}`);
        } finally {
            setIsGenerating(false);
        }
    };

    const generateAIImage = async (prompt, width = 512, height = 512, style = 'realistic', model = 'auto', fallbackToSVG = true, quality = 'medium') => {
        setIsGenerating(true);
        try {
            const response = await fetch('/api/multimedia_tool', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'generate_ai_image',
                    prompt,
                    width,
                    height,
                    style,
                    model,
                    fallbackToSVG,
                    generationQuality: quality
                })
            });
            
            const result = await response.json();
            if (result.structuredContent.success) {
                // Load the generated image into a new session
                await loadSessions();
                setCurrentView('sessions');
            } else {
                setError(result.structuredContent.message);
            }
        } catch (error) {
            setError(`AI image generation failed: ${error.message}`);
        } finally {
            setIsGenerating(false);
        }
    };

    const handleGenerate = async () => {
        if (!generationPrompt.trim()) {
            setError('Please enter a prompt for generation');
            return;
        }

        if (generationType === 'svg') {
            await generateSVG(generationPrompt);
        } else {
            await generateAIImage(generationPrompt);
        }
        
        setGenerationPrompt('');
    };

    // Load status and audio devices on mount
    useEffect(() => {
        loadStatus();
        loadAudioDevices();
    }, []);

    return (
        <div className="multimedia-tool">
            {/* Header */}
            <header className="tool-header">
                <div className="header-left">
                    <button 
                        className="menu-toggle"
                        onClick={() => setSidebarOpen(!sidebarOpen)}
                    >
                        <i data-lucide="menu"></i>
                    </button>
                    <h1>Multimedia Tool</h1>
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
                    
                    {/* Recording Controls */}
                    <div className="recording-controls">
                        <button 
                            className={`btn ${isRecording ? 'btn-danger' : 'btn-success'}`}
                            onClick={() => recordWhatsPlaying(30)}
                            disabled={isRecording}
                        >
                            <i data-lucide={isRecording ? "square" : "mic"}></i>
                            {isRecording ? 'Recording...' : 'Record What\'s Playing'}
                        </button>
                        
                        <button 
                            className="btn btn-secondary"
                            onClick={() => recordMicrophone(30)}
                            disabled={isRecording}
                        >
                            <i data-lucide="mic"></i>
                            Record Mic
                        </button>
                    </div>
                    
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

            <div className="tool-content">
                {/* Sidebar */}
                {sidebarOpen && (
                    <aside className="sidebar">
                        <div className="sidebar-section">
                            <h3>Media Types</h3>
                            <div className="media-type-buttons">
                                <button 
                                    className={`media-type-btn ${selectedTool === 'audio' ? 'active' : ''}`}
                                    onClick={() => setSelectedTool('audio')}
                                >
                                    <i data-lucide="music"></i>
                                    Audio
                                </button>
                                <button 
                                    className={`media-type-btn ${selectedTool === 'image' ? 'active' : ''}`}
                                    onClick={() => setSelectedTool('image')}
                                >
                                    <i data-lucide="image"></i>
                                    Image
                                </button>
                                <button 
                                    className={`media-type-btn ${selectedTool === 'video' ? 'active' : ''}`}
                                    onClick={() => setSelectedTool('video')}
                                >
                                    <i data-lucide="video"></i>
                                    Video
                                </button>
                            </div>
                        </div>

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

                        {currentView === 'projects' && (
                            <div className="sidebar-section">
                                <h3>Projects ({projects.length})</h3>
                                <div className="project-list">
                                    {projects.map(project => (
                                        <div 
                                            key={project.name}
                                            className={`project-item ${activeProject?.name === project.name ? 'active' : ''}`}
                                            onClick={() => setActiveProject(project)}
                                        >
                                            <div className="project-name">{project.name}</div>
                                            <div className="project-info">
                                                <span className="project-type">{project.type}</span>
                                                <span className="project-sessions">{project.sessionCount} sessions</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                                <button 
                                    className="btn btn-primary btn-full"
                                    onClick={() => {
                                        const name = prompt('Project name:');
                                        const type = prompt('Project type (audio/image/video/mixed):');
                                        if (name && type) {
                                            createProject(name, type, []);
                                        }
                                    }}
                                >
                                    <i data-lucide="plus"></i>
                                    New Project
                                </button>
                            </div>
                        )}

                        {/* Recording Panel */}
                            <div className="sidebar-section">
                                <h3>Audio Recording</h3>
                                <RecordingPanel
                                    audioDevices={audioDevices}
                                    isRecording={isRecording}
                                    onRecordWhatsPlaying={recordWhatsPlaying}
                                    onRecordMicrophone={recordMicrophone}
                                    onStartRecording={startRecording}
                                />
                            </div>

                            <div className="sidebar-section">
                                <h3>Content Generation</h3>
                                <GenerationPanel
                                    isGenerating={isGenerating}
                                    generationPrompt={generationPrompt}
                                    setGenerationPrompt={setGenerationPrompt}
                                    generationType={generationType}
                                    setGenerationType={setGenerationType}
                                    onGenerate={handleGenerate}
                                    onGenerateSVG={generateSVG}
                                    onGenerateAIImage={generateAIImage}
                                />
                            </div>

                        {currentView === 'editor' && activeSession && (
                            <>
                                <div className="sidebar-section">
                                    <h3>Operations</h3>
                                    <OperationPanel 
                                        sessionType={activeSession.type}
                                        onApply={applyOperation}
                                    />
                                </div>

                                <div className="sidebar-section">
                                    <h3>Export</h3>
                                    <ExportPanel 
                                        sessionType={activeSession.type}
                                        onExport={exportMedia}
                                    />
                                </div>
                            </>
                        )}
                    </aside>
                )}

                {/* Main Content Area */}
                <main className="main-content">
                    {currentView === 'sessions' && (
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
                                        onClick={() => fileInputRef.current?.click()}
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
                                            onClick={() => {
                                                setActiveSession(session);
                                                setCurrentView('editor');
                                            }}
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
                    )}

                    {currentView === 'projects' && (
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
                                    <button 
                                        className="btn btn-primary"
                                        onClick={() => {
                                            const name = prompt('Project name:');
                                            const type = prompt('Project type (audio/image/video/mixed):');
                                            if (name && type) {
                                                createProject(name, type, []);
                                            }
                                        }}
                                    >
                                        <i data-lucide="plus"></i>
                                        Create Project
                                    </button>
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
                    )}

                    {currentView === 'editor' && (
                        <div className="editor-view">
                            {!activeSession ? (
                                <div className="empty-state">
                                    <i data-lucide="edit" className="empty-icon"></i>
                                    <h3>No Media Selected</h3>
                                    <p>Select a session from the sidebar or upload new media</p>
                                    <button 
                                        className="btn btn-primary"
                                        onClick={() => fileInputRef.current?.click()}
                                    >
                                        <i data-lucide="upload"></i>
                                        Open Media
                                    </button>
                                </div>
                            ) : (
                                <div className="editor-workspace">
                                    <div className="editor-header">
                                        <h3>{activeSession.name}</h3>
                                        <span className="session-type-badge">{activeSession.type.toUpperCase()}</span>
                                    </div>
                                    
                                    <div 
                                        className="media-preview"
                                        onDrop={handleDrop}
                                        onDragOver={handleDragOver}
                                    >
                                        {activeSession.type === 'image' && (
                                            <div className="image-preview">
                                                <img 
                                                    src={`/api/multimedia/session/${activeSession.sessionId}`}
                                                    alt={activeSession.name}
                                                    className="preview-image"
                                                />
                                            </div>
                                        )}
                                        
                                        {activeSession.type === 'audio' && (
                                            <div className="audio-preview">
                                                <div className="audio-visualizer">
                                                    <i data-lucide="music" className="audio-icon"></i>
                                                </div>
                                                <audio 
                                                    ref={audioRef}
                                                    src={`/api/multimedia/session/${activeSession.sessionId}`}
                                                    controls
                                                    className="audio-player"
                                                />
                                            </div>
                                        )}
                                        
                                        {activeSession.type === 'video' && (
                                            <div className="video-preview">
                                                <video 
                                                    ref={videoRef}
                                                    src={`/api/multimedia/session/${activeSession.sessionId}`}
                                                    controls
                                                    className="video-player"
                                                />
                                            </div>
                                        )}
                                    </div>
                                    
                                    <div className="editor-info">
                                        <div className="info-item">
                                            <label>Type:</label>
                                            <span>{activeSession.type}</span>
                                        </div>
                                        <div className="info-item">
                                            <label>Layers:</label>
                                            <span>{activeSession.layers}</span>
                                        </div>
                                        <div className="info-item">
                                            <label>Modified:</label>
                                            <span>{new Date(activeSession.modifiedAt).toLocaleString()}</span>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
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

// Operation Panel Component
function OperationPanel({ sessionType, onApply }) {
    const [operation, setOperation] = useState('');
    const [params, setParams] = useState({});

    const operations = {
        audio: [
            { name: 'trim', label: 'Trim', params: ['start', 'end'] },
            { name: 'normalize', label: 'Normalize', params: [] },
            { name: 'fade', label: 'Fade', params: ['fadeIn', 'fadeOut'] },
            { name: 'gain', label: 'Gain', params: ['gainDb'] },
            { name: 'reverse', label: 'Reverse', params: [] }
        ],
        image: [
            { name: 'resize', label: 'Resize', params: ['width', 'height'] },
            { name: 'crop', label: 'Crop', params: ['x', 'y', 'width', 'height'] },
            { name: 'rotate', label: 'Rotate', params: ['angle'] },
            { name: 'flip', label: 'Flip', params: ['direction'] },
            { name: 'filter', label: 'Filter', params: ['type'] }
        ],
        video: [
            { name: 'cut', label: 'Cut', params: ['start', 'end'] },
            { name: 'resize_video', label: 'Resize', params: ['width', 'height'] },
            { name: 'convert', label: 'Convert', params: ['format'] }
        ]
    };

    const currentOps = operations[sessionType] || [];

    const handleApply = () => {
        if (operation) {
            onApply(operation, params);
            setOperation('');
            setParams({});
        }
    };

    return (
        <div className="operation-panel">
            <select 
                value={operation}
                onChange={(e) => setOperation(e.target.value)}
                className="operation-select"
            >
                <option value="">Select Operation</option>
                {currentOps.map(op => (
                    <option key={op.name} value={op.name}>{op.label}</option>
                ))}
            </select>
            
            {operation && (
                <div className="operation-params">
                    {currentOps.find(op => op.name === operation)?.params.map(param => (
                        <div key={param} className="param-group">
                            <label>{param}:</label>
                            <input
                                type={param.includes('width') || param.includes('height') || param.includes('angle') ? 'number' : 'text'}
                                value={params[param] || ''}
                                onChange={(e) => setParams(prev => ({ ...prev, [param]: e.target.value }))}
                                placeholder={`Enter ${param}`}
                            />
                        </div>
                    ))}
                </div>
            )}
            
            <button 
                className="btn btn-primary btn-full"
                onClick={handleApply}
                disabled={!operation}
            >
                Apply Operation
            </button>
        </div>
    );
}

// Export Panel Component
function ExportPanel({ sessionType, onExport }) {
    const [format, setFormat] = useState('');
    const [quality, setQuality] = useState(80);

    const formats = {
        audio: ['mp3', 'wav', 'flac', 'aac', 'ogg'],
        image: ['jpg', 'png', 'gif', 'webp', 'tiff'],
        video: ['mp4', 'avi', 'mov', 'mkv', 'webm']
    };

    const currentFormats = formats[sessionType] || [];

    const handleExport = () => {
        if (format) {
            onExport(format, quality);
        }
    };

    return (
        <div className="export-panel">
            <div className="format-group">
                <label>Format:</label>
                <select 
                    value={format}
                    onChange={(e) => setFormat(e.target.value)}
                    className="format-select"
                >
                    <option value="">Select Format</option>
                    {currentFormats.map(fmt => (
                        <option key={fmt} value={fmt}>{fmt.toUpperCase()}</option>
                    ))}
                </select>
            </div>
            
            <div className="quality-group">
                <label>Quality: {quality}%</label>
                <input
                    type="range"
                    min="1"
                    max="100"
                    value={quality}
                    onChange={(e) => setQuality(parseInt(e.target.value))}
                    className="quality-slider"
                />
            </div>
            
            <button 
                className="btn btn-primary btn-full"
                onClick={handleExport}
                disabled={!format}
            >
                <i data-lucide="download"></i>
                Export
            </button>
        </div>
    );
}

// Recording Panel Component
function RecordingPanel({ audioDevices, isRecording, onRecordWhatsPlaying, onRecordMicrophone, onStartRecording }) {
    const [duration, setDuration] = useState(30);
    const [format, setFormat] = useState('wav');
    const [quality, setQuality] = useState(80);
    const [deviceType, setDeviceType] = useState('auto');

    const stereoMixDevices = audioDevices.filter(d => d.type === 'stereo_mix');
    const micDevices = audioDevices.filter(d => d.type === 'microphone');

    const handleRecord = () => {
        onStartRecording(deviceType, duration, format, quality);
    };

    return (
        <div className="recording-panel">
            <div className="recording-status">
                {isRecording ? (
                    <div className="recording-indicator">
                        <div className="recording-dot"></div>
                        <span>Recording in progress...</span>
                    </div>
                ) : (
                    <div className="recording-ready">
                        <i data-lucide="mic"></i>
                        <span>Ready to record</span>
                    </div>
                )}
            </div>

            <div className="recording-options">
                <div className="device-type-group">
                    <label>Recording Source:</label>
                    <select 
                        value={deviceType}
                        onChange={(e) => setDeviceType(e.target.value)}
                        className="device-type-select"
                    >
                        <option value="auto">Auto-detect</option>
                        <option value="stereo_mix">Stereo Mix (What's Playing)</option>
                        <option value="microphone">Microphone</option>
                    </select>
                </div>

                <div className="duration-group">
                    <label>Duration: {duration}s</label>
                    <input
                        type="range"
                        min="5"
                        max="300"
                        value={duration}
                        onChange={(e) => setDuration(parseInt(e.target.value))}
                        className="duration-slider"
                    />
                </div>

                <div className="format-group">
                    <label>Format:</label>
                    <select 
                        value={format}
                        onChange={(e) => setFormat(e.target.value)}
                        className="format-select"
                    >
                        <option value="wav">WAV (Uncompressed)</option>
                        <option value="mp3">MP3 (Compressed)</option>
                        <option value="flac">FLAC (Lossless)</option>
                        <option value="aac">AAC (Compressed)</option>
                    </select>
                </div>

                {format !== 'wav' && format !== 'flac' && (
                    <div className="quality-group">
                        <label>Quality: {quality}%</label>
                        <input
                            type="range"
                            min="1"
                            max="100"
                            value={quality}
                            onChange={(e) => setQuality(parseInt(e.target.value))}
                            className="quality-slider"
                        />
                    </div>
                )}
            </div>

            <div className="recording-buttons">
                <button 
                    className="btn btn-success btn-full"
                    onClick={() => onRecordWhatsPlaying(duration)}
                    disabled={isRecording}
                >
                    <i data-lucide="speakers"></i>
                    Record What's Playing
                </button>
                
                <button 
                    className="btn btn-secondary btn-full"
                    onClick={() => onRecordMicrophone(duration)}
                    disabled={isRecording}
                >
                    <i data-lucide="mic"></i>
                    Record Microphone
                </button>
                
                <button 
                    className="btn btn-primary btn-full"
                    onClick={handleRecord}
                    disabled={isRecording}
                >
                    <i data-lucide={isRecording ? "square" : "circle"}></i>
                    {isRecording ? 'Recording...' : 'Start Recording'}
                </button>
            </div>

            {audioDevices.length > 0 && (
                <div className="available-devices">
                    <h4>Available Devices:</h4>
                    <div className="device-list">
                        {stereoMixDevices.length > 0 && (
                            <div className="device-category">
                                <h5>Stereo Mix:</h5>
                                {stereoMixDevices.map((device, index) => (
                                    <div key={index} className="device-item">
                                        <i data-lucide="speakers"></i>
                                        <span>{device.name}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                        
                        {micDevices.length > 0 && (
                            <div className="device-category">
                                <h5>Microphones:</h5>
                                {micDevices.map((device, index) => (
                                    <div key={index} className="device-item">
                                        <i data-lucide="mic"></i>
                                        <span>{device.name}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}

// Generation Panel Component
function GenerationPanel({ isGenerating, generationPrompt, setGenerationPrompt, generationType, setGenerationType, onGenerate, onGenerateSVG, onGenerateAIImage }) {
    const [width, setWidth] = useState(800);
    const [height, setHeight] = useState(600);
    const [style, setStyle] = useState('minimal');
    const [model, setModel] = useState('auto');
    const [fallbackToSVG, setFallbackToSVG] = useState(true);
    const [quality, setQuality] = useState('medium');

    const handleQuickGenerate = async (type) => {
        if (!generationPrompt.trim()) {
            return;
        }

        if (type === 'svg') {
            await onGenerateSVG(generationPrompt, width, height, style);
        } else {
            await onGenerateAIImage(generationPrompt, width, height, style, model, fallbackToSVG, quality);
        }
    };

    return (
        <div className="generation-panel">
            <div className="generation-status">
                {isGenerating ? (
                    <div className="generating-indicator">
                        <div className="generating-spinner"></div>
                        <span>Generating content...</span>
                    </div>
                ) : (
                    <div className="generation-ready">
                        <i data-lucide="sparkles"></i>
                        <span>Ready to generate</span>
                    </div>
                )}
            </div>

            <div className="generation-options">
                <div className="prompt-group">
                    <label>Prompt:</label>
                    <textarea
                        value={generationPrompt}
                        onChange={(e) => setGenerationPrompt(e.target.value)}
                        placeholder="Describe what you want to generate..."
                        className="prompt-textarea"
                        rows="3"
                    />
                </div>

                <div className="type-group">
                    <label>Generation Type:</label>
                    <select 
                        value={generationType}
                        onChange={(e) => setGenerationType(e.target.value)}
                        className="type-select"
                    >
                        <option value="svg">SVG (Vector Graphics)</option>
                        <option value="ai_image">AI Image (Bitmap)</option>
                    </select>
                </div>

                <div className="dimensions-group">
                    <label>Dimensions:</label>
                    <div className="dimension-inputs">
                        <input
                            type="number"
                            value={width}
                            onChange={(e) => setWidth(parseInt(e.target.value))}
                            placeholder="Width"
                            className="dimension-input"
                        />
                        <span>×</span>
                        <input
                            type="number"
                            value={height}
                            onChange={(e) => setHeight(parseInt(e.target.value))}
                            placeholder="Height"
                            className="dimension-input"
                        />
                    </div>
                </div>

                <div className="style-group">
                    <label>Style:</label>
                    <select 
                        value={style}
                        onChange={(e) => setStyle(e.target.value)}
                        className="style-select"
                    >
                        <option value="minimal">Minimal</option>
                        <option value="geometric">Geometric</option>
                        <option value="organic">Organic</option>
                        <option value="technical">Technical</option>
                        <option value="artistic">Artistic</option>
                        <option value="detailed">Detailed</option>
                        <option value="realistic">Realistic</option>
                        <option value="cartoon">Cartoon</option>
                        <option value="abstract">Abstract</option>
                        <option value="photographic">Photographic</option>
                        <option value="digital_art">Digital Art</option>
                    </select>
                </div>

                {generationType === 'ai_image' && (
                    <>
                        <div className="model-group">
                            <label>AI Model:</label>
                            <select 
                                value={model}
                                onChange={(e) => setModel(e.target.value)}
                                className="model-select"
                            >
                                <option value="auto">Auto-detect</option>
                                <option value="dall-e-2">DALL-E 2</option>
                                <option value="dall-e-3">DALL-E 3</option>
                                <option value="stable-diffusion-xl">Stable Diffusion XL</option>
                                <option value="stable-diffusion-1.5">Stable Diffusion 1.5</option>
                            </select>
                        </div>

                        <div className="quality-group">
                            <label>Quality:</label>
                            <select 
                                value={quality}
                                onChange={(e) => setQuality(e.target.value)}
                                className="quality-select"
                            >
                                <option value="low">Low</option>
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                            </select>
                        </div>

                        <div className="fallback-group">
                            <label>
                                <input
                                    type="checkbox"
                                    checked={fallbackToSVG}
                                    onChange={(e) => setFallbackToSVG(e.target.checked)}
                                />
                                Fallback to SVG if model not supported
                            </label>
                        </div>
                    </>
                )}
            </div>

            <div className="generation-buttons">
                <button 
                    className="btn btn-primary btn-full"
                    onClick={onGenerate}
                    disabled={isGenerating || !generationPrompt.trim()}
                >
                    <i data-lucide="sparkles"></i>
                    Generate {generationType === 'svg' ? 'SVG' : 'AI Image'}
                </button>
                
                <div className="quick-generate-buttons">
                    <button 
                        className="btn btn-secondary"
                        onClick={() => handleQuickGenerate('svg')}
                        disabled={isGenerating || !generationPrompt.trim()}
                    >
                        <i data-lucide="vector"></i>
                        Quick SVG
                    </button>
                    
                    <button 
                        className="btn btn-secondary"
                        onClick={() => handleQuickGenerate('ai_image')}
                        disabled={isGenerating || !generationPrompt.trim()}
                    >
                        <i data-lucide="image"></i>
                        Quick AI
                    </button>
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
ReactDOM.render(<MultimediaTool />, document.getElementById('root'));
