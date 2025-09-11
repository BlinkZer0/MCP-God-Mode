class AudioEditor {
    constructor() {
        this.currentSession = null;
        this.wavesurfer = null;
        this.isRecording = false;
        this.recordingStartTime = null;
        this.recordingTimer = null;
        
        this.initializeElements();
        this.attachEventListeners();
        this.loadAudioDevices();
    }
    
    initializeElements() {
        // File input
        this.fileInput = document.getElementById('file-input');
        
        // Buttons
        this.recordBtn = document.getElementById('record-btn');
        this.exportBtn = document.getElementById('export-btn');
        this.clearBtn = document.getElementById('clear-btn');
        this.playBtn = document.getElementById('play-btn');
        this.pauseBtn = document.getElementById('pause-btn');
        this.stopBtn = document.getElementById('stop-btn');
        
        // Recording controls
        this.durationInput = document.getElementById('duration-input');
        this.deviceSelect = document.getElementById('device-select');
        this.formatSelect = document.getElementById('format-select');
        this.recordingStatus = document.getElementById('recording-status');
        
        // Export controls
        this.exportFormat = document.getElementById('export-format');
        this.bitrateInput = document.getElementById('bitrate-input');
        
        // Display elements
        this.sessionDetails = document.getElementById('session-details');
        this.editsList = document.getElementById('edits-list');
        this.timeDisplay = document.getElementById('time-display');
        this.waveformContainer = document.getElementById('waveform-container');
        this.loading = document.getElementById('loading');
        this.errorMessage = document.getElementById('error-message');
        this.successMessage = document.getElementById('success-message');
    }
    
    attachEventListeners() {
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        this.recordBtn.addEventListener('click', () => this.toggleRecording());
        this.exportBtn.addEventListener('click', () => this.exportAudio());
        this.clearBtn.addEventListener('click', () => this.clearSession());
        this.playBtn.addEventListener('click', () => this.play());
        this.pauseBtn.addEventListener('click', () => this.pause());
        this.stopBtn.addEventListener('click', () => this.stop());
    }
    
    async loadAudioDevices() {
        try {
            const devices = await navigator.mediaDevices.enumerateDevices();
            const audioInputs = devices.filter(device => device.kind === 'audioinput');
            
            this.deviceSelect.innerHTML = '<option value="default">Default Device</option>';
            audioInputs.forEach(device => {
                const option = document.createElement('option');
                option.value = device.deviceId;
                option.textContent = device.label || `Microphone ${device.deviceId.slice(0, 8)}`;
                this.deviceSelect.appendChild(option);
            });
        } catch (error) {
            console.warn('Could not load audio devices:', error);
        }
    }
    
    async handleFileSelect(event) {
        const file = event.target.files[0];
        if (!file) return;
        
        this.showLoading();
        
        try {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('sessionName', file.name);
            
            const response = await fetch('/api/audio/import', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const result = await response.json();
            this.currentSession = result;
            
            await this.loadWaveform(file);
            this.updateSessionInfo();
            this.enableControls();
            
            this.showSuccess('Audio file loaded successfully');
        } catch (error) {
            this.showError(`Failed to load audio file: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }
    
    async loadWaveform(file) {
        // Clear existing waveform
        if (this.wavesurfer) {
            this.wavesurfer.destroy();
        }
        
        // Create new waveform container
        const waveformEl = document.createElement('div');
        waveformEl.id = 'waveform';
        this.waveformContainer.innerHTML = '';
        this.waveformContainer.appendChild(waveformEl);
        
        // Initialize WaveSurfer
        this.wavesurfer = WaveSurfer.create({
            container: '#waveform',
            waveColor: '#4a9eff',
            progressColor: '#2e6bd9',
            cursorColor: '#ffffff',
            barWidth: 2,
            barGap: 1,
            height: 200,
            normalize: true,
            responsive: true
        });
        
        // Load audio file
        const url = URL.createObjectURL(file);
        await this.wavesurfer.load(url);
        
        // Update time display
        this.wavesurfer.on('audioprocess', () => {
            this.updateTimeDisplay();
        });
        
        this.wavesurfer.on('seek', () => {
            this.updateTimeDisplay();
        });
        
        this.wavesurfer.on('finish', () => {
            this.stop();
        });
    }
    
    async toggleRecording() {
        if (this.isRecording) {
            await this.stopRecording();
        } else {
            await this.startRecording();
        }
    }
    
    async startRecording() {
        const duration = parseInt(this.durationInput.value) || 30;
        const device = this.deviceSelect.value;
        const format = this.formatSelect.value;
        
        try {
            this.isRecording = true;
            this.recordingStartTime = Date.now();
            this.recordingStatus.classList.add('active');
            this.recordBtn.textContent = '⏹️ Stop Recording';
            this.recordBtn.style.background = '#ff4444';
            
            // Start recording timer
            this.recordingTimer = setInterval(() => {
                const elapsed = Math.floor((Date.now() - this.recordingStartTime) / 1000);
                const remaining = Math.max(0, duration - elapsed);
                this.recordingStatus.textContent = `🔴 Recording... ${remaining}s remaining`;
                
                if (remaining === 0) {
                    this.stopRecording();
                }
            }, 1000);
            
            // Call recording API
            const response = await fetch('/api/audio/record', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    duration: duration,
                    device: device,
                    format: format,
                    sampleRate: 44100,
                    channels: 2,
                    quality: 'high',
                    enableMonitoring: true,
                    sessionName: `Recording_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}`
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const result = await response.json();
            this.currentSession = result;
            
            // Load the recorded audio
            await this.loadRecordedAudio(result);
            this.updateSessionInfo();
            this.enableControls();
            
            this.showSuccess('Recording completed successfully');
        } catch (error) {
            this.showError(`Recording failed: ${error.message}`);
            this.stopRecording();
        }
    }
    
    async stopRecording() {
        this.isRecording = false;
        this.recordingStatus.classList.remove('active');
        this.recordBtn.textContent = '🎤 Record';
        this.recordBtn.style.background = '#4a9eff';
        
        if (this.recordingTimer) {
            clearInterval(this.recordingTimer);
            this.recordingTimer = null;
        }
    }
    
    async loadRecordedAudio(session) {
        // For recorded audio, we need to fetch the audio file
        // This would typically be done through a separate endpoint
        // For now, we'll simulate loading the recorded audio
        this.showLoading();
        
        try {
            // In a real implementation, you would fetch the recorded audio file
            // const response = await fetch(`/api/audio/session/${session.sessionId}/audio`);
            // const audioBlob = await response.blob();
            
            // For demo purposes, create a silent audio file
            const audioContext = new AudioContext();
            const sampleRate = 44100;
            const duration = session.durationSec || 30;
            const buffer = audioContext.createBuffer(2, sampleRate * duration, sampleRate);
            
            const audioBlob = await this.audioBufferToWav(buffer);
            const file = new File([audioBlob], 'recording.wav', { type: 'audio/wav' });
            
            await this.loadWaveform(file);
        } catch (error) {
            this.showError(`Failed to load recorded audio: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }
    
    async audioBufferToWav(buffer) {
        const length = buffer.length;
        const arrayBuffer = new ArrayBuffer(44 + length * 2);
        const view = new DataView(arrayBuffer);
        
        // WAV header
        const writeString = (offset, string) => {
            for (let i = 0; i < string.length; i++) {
                view.setUint8(offset + i, string.charCodeAt(i));
            }
        };
        
        writeString(0, 'RIFF');
        view.setUint32(4, 36 + length * 2, true);
        writeString(8, 'WAVE');
        writeString(12, 'fmt ');
        view.setUint32(16, 16, true);
        view.setUint16(20, 1, true);
        view.setUint16(22, 2, true);
        view.setUint32(24, 44100, true);
        view.setUint32(28, 44100 * 2 * 2, true);
        view.setUint16(32, 2 * 2, true);
        view.setUint16(34, 16, true);
        writeString(36, 'data');
        view.setUint32(40, length * 2, true);
        
        // Convert audio data
        const channelData = buffer.getChannelData(0);
        let offset = 44;
        for (let i = 0; i < length; i++) {
            const sample = Math.max(-1, Math.min(1, channelData[i]));
            view.setInt16(offset, sample * 0x7FFF, true);
            offset += 2;
        }
        
        return new Blob([arrayBuffer], { type: 'audio/wav' });
    }
    
    play() {
        if (this.wavesurfer) {
            this.wavesurfer.play();
            this.playBtn.disabled = true;
            this.pauseBtn.disabled = false;
        }
    }
    
    pause() {
        if (this.wavesurfer) {
            this.wavesurfer.pause();
            this.playBtn.disabled = false;
            this.pauseBtn.disabled = true;
        }
    }
    
    stop() {
        if (this.wavesurfer) {
            this.wavesurfer.stop();
            this.playBtn.disabled = false;
            this.pauseBtn.disabled = true;
        }
    }
    
    async exportAudio() {
        if (!this.currentSession) {
            this.showError('No session to export');
            return;
        }
        
        this.showLoading();
        
        try {
            const format = this.exportFormat.value;
            const bitrate = parseInt(this.bitrateInput.value) || 192;
            
            const response = await fetch('/api/audio/export', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    sessionId: this.currentSession.sessionId,
                    format: format,
                    bitRateKbps: bitrate
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const result = await response.json();
            
            // Download the exported file
            const link = document.createElement('a');
            link.href = result.outputPath;
            link.download = `exported_audio.${format}`;
            link.click();
            
            this.showSuccess(`Audio exported successfully as ${format.toUpperCase()}`);
        } catch (error) {
            this.showError(`Export failed: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }
    
    clearSession() {
        this.currentSession = null;
        
        if (this.wavesurfer) {
            this.wavesurfer.destroy();
            this.wavesurfer = null;
        }
        
        this.waveformContainer.innerHTML = '<div class="loading" id="loading"><div class="spinner"></div><div>Processing audio...</div></div>';
        this.hideLoading();
        
        this.updateSessionInfo();
        this.disableControls();
        
        this.showSuccess('Session cleared');
    }
    
    updateSessionInfo() {
        if (this.currentSession) {
            this.sessionDetails.innerHTML = `
                <div><strong>Name:</strong> ${this.currentSession.name}</div>
                <div><strong>Duration:</strong> ${this.currentSession.durationSec ? this.formatTime(this.currentSession.durationSec) : 'Unknown'}</div>
                <div><strong>Sample Rate:</strong> ${this.currentSession.sampleRate || 'Unknown'} Hz</div>
                <div><strong>Channels:</strong> ${this.currentSession.channels || 'Unknown'}</div>
                <div><strong>Format:</strong> ${this.currentSession.format || 'Unknown'}</div>
            `;
        } else {
            this.sessionDetails.textContent = 'No session loaded';
        }
    }
    
    updateTimeDisplay() {
        if (this.wavesurfer) {
            const current = this.wavesurfer.getCurrentTime();
            const duration = this.wavesurfer.getDuration();
            this.timeDisplay.textContent = `${this.formatTime(current)} / ${this.formatTime(duration)}`;
        }
    }
    
    formatTime(seconds) {
        const mins = Math.floor(seconds / 60);
        const secs = Math.floor(seconds % 60);
        return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    
    enableControls() {
        this.exportBtn.disabled = false;
        this.playBtn.disabled = false;
        this.pauseBtn.disabled = true;
        this.stopBtn.disabled = false;
    }
    
    disableControls() {
        this.exportBtn.disabled = true;
        this.playBtn.disabled = true;
        this.pauseBtn.disabled = true;
        this.stopBtn.disabled = true;
    }
    
    showLoading() {
        this.loading.classList.add('active');
    }
    
    hideLoading() {
        this.loading.classList.remove('active');
    }
    
    showError(message) {
        this.errorMessage.textContent = message;
        this.errorMessage.classList.add('active');
        setTimeout(() => {
            this.errorMessage.classList.remove('active');
        }, 5000);
    }
    
    showSuccess(message) {
        this.successMessage.textContent = message;
        this.successMessage.classList.add('active');
        setTimeout(() => {
            this.successMessage.classList.remove('active');
        }, 3000);
    }
}

// Initialize the audio editor when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new AudioEditor();
});

// Service Worker registration for PWA
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then((registration) => {
                console.log('SW registered: ', registration);
            })
            .catch((registrationError) => {
                console.log('SW registration failed: ', registrationError);
            });
    });
}
