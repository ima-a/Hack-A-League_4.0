# SwarmShield UI - Installation & Quick Start Guide

## 🎯 What's Included

A complete React-based dashboard for monitoring SwarmShield's autonomous cybersecurity agents with:
- ✅ Blinking alert system with threat levels
- ✅ Real-time network logs viewer
- ✅ Expandable agent insight panels (Scout, Analyzer, Responder, Evolver)
- ✅ Agent-to-agent communication toggles
- ✅ Complete agent documentation with descriptions
- ✅ Stunning black/white/red color scheme
- ✅ Smooth animations with Framer Motion
- ✅ Responsive design for all screen sizes

## 🚀 Installation

### Step 1: Prerequisites
Make sure you have Node.js installed:
```bash
node --version  # Should be v14 or higher
npm --version
```

### Step 2: Install Dependencies
```bash
cd swarmshield/ui
npm install
```

This installs:
- React & React DOM
- Framer Motion (animations)
- React Icons
- Axios (for API calls)

### Step 3: Start Development Server
```bash
npm start
```

Your browser will automatically open at: **http://localhost:3000**

## 📺 Dashboard Features at a Glance

### 🔴 Alert System
- **Shows current threat level**: Normal (green) → Medium (orange) → Critical (red)
- **Blinking button** when critical (it pulsates and changes intensity)
- **Real-time stats** showing detected threats, attack vectors, response rate

### 🔍 Network Logs
- Displays live-streaming network traffic logs
- Columns: Time | Source IP | Destination | Threat Type | Severity | Packets | Status
- New logs appear at the top every 2 seconds
- Color-coded by severity (Critical=Red, High=Orange, etc.)
- **Clear Logs** button to reset the view

### 🤖 Agent Insight Panels (Click to Expand!)
Each accordion-style card shows:

1. **Scout 🔭** (Network Detective)
   - What it's thinking: "Monitoring network traffic for anomalies..."
   - Key Metrics: Detections count, Confidence %
   - Insights: DDoS detected, Port scan activity, Exfiltration patterns
   - Connected to → Analyzer

2. **Analyzer 🧬** (Threat Correlator)
   - What it's thinking: "Correlating threat patterns across network..."
   - Key Metrics: Correlations count, Risk Score %
   - Insights: Attack graph built, Lateral movement risk, Coordinated attacks
   - Connected to → Responder

3. **Responder ⚡** (Defense Executor)
   - What it's thinking: "Executing defensive actions..."
   - Key Metrics: Actions executed count, IPs blocked count
   - Insights: 5 IPs blocked, Honeypot engaged, Traffic redirected
   - Connected to → Evolver

4. **Evolver 🔮 (Mahoraga)** (Strategy Optimizer)
   - What it's thinking: "Adapting to new attack patterns..."
   - Key Metrics: Generation count, Fitness score %
   - Insights: Thresholds optimized, Adaptation rating, Blind spots identified
   - Connected to → Scout

### 🔗 Communication Control Panel
Toggle switches to enable/disable agent communications:
- Scout → Analyzer (Threat detection flow)
- Analyzer → Responder (Action recommendations)
- Responder → Evolver (Defense feedback)
- Evolver → Scout (Threshold evolution)
- All Agents Synchronized (Consensus mode)

Shows:
- Number of active connections
- Network status: HEALTHY

### 📚 Agent Documentation Button
Click "📖 View Agent Documentation" to see comprehensive details about each agent:
- Full name and description
- Primary responsibilities
- Detection/Analysis methods
- Key performance metrics
- Information flow diagram
- **Special Mahoraga reference** with GIF placeholder

## 🎮 How to Use

### 1. Monitor Threats in Real-Time
- Watch the **Alert System** at the top for threat level changes
- Check the **Network Logs** to see all detected threats
- Log shows: timestamp, source IP, destination, threat type, severity, packet count, and action taken

### 2. View Agent Insights
- **Click any agent card** to expand and see what it's thinking
- Each agent shows its current metrics and latest insights
- Metrics update every 8 seconds with simulated data

### 3. Control Agent Communication
- **Toggle switches** to enable/disable connections between agents
- See real-time animation when enabled (pulsing lines)
- Monitor active connection count

### 4. Learn About Agents
- **Click "View Agent Documentation"** button
- **Click agent tabs** (Scout, Analyzer, Responder, Evolver/Mahoraga)
- Read complete breakdowns of what each agent does

## 🎨 Color & Design

### Color Scheme
- **Black Background**: `#0a0e27` (main), `#1a1f3a` (secondary)
- **Red Alerts**: `#ff1744` (primary), `#ff5252` (hover)
- **Agent Colors**:
  - Scout: Cyan (`#00bcd4`)
  - Analyzer: Purple (`#9c27b0`)
  - Responder: Orange (`#ff5722`)
  - Evolver/Mahoraga: Red (`#f44336`)

### Animations
- **Blinking alert**: Pulses when threat level is critical
- **Agent panels**: Smooth expand/collapse transitions
- **Status indicators**: Continuous pulse animation
- **Log entries**: Slide in from left with fade effect
- **Toggle switches**: Smooth color and position transitions

## 📊 Mock Data Explanation

The current dashboard shows **simulated data** that updates automatically:
- Log entries generated every 2 seconds
- Agent metrics update every 8 seconds
- Threat level changes every 30 seconds
- All data is randomized for demo purposes

### When Connected to Real Backend
Replace mock data generators with actual API calls. Example:
```javascript
// In AgentPanels.js or Dashboard.js
useEffect(() => {
  const fetchAgentData = async () => {
    const response = await axios.get('/api/agents/scout');
    setAgents(prev => ({...prev, scout: response.data}));
  };
  fetchAgentData();
}, []);
```

## 🔧 Building for Production

```bash
# Create optimized production build
npm run build

# This creates a 'build/' folder with everything ready to deploy
# Upload this folder to your web server or hosting platform
```

## 📱 Responsive Design

The dashboard automatically adapts to screen size:
- **Desktop** (1200px+): Full layout with 4-column agent grid
- **Tablet** (768-1199px): 2-column agent grid
- **Mobile** (<768px): Single column, stacked components

## 🆘 Troubleshooting

### Port 3000 is already in use?
```bash
PORT=3001 npm start  # Use different port
```

### Dependencies not installing?
```bash
# Clear npm cache and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Hot reload not working?
```bash
# Kill the process and restart
npm start
```

### Application is slow?
- Close browser tabs to free memory
- Run production build: `npm build`
- Check browser DevTools → Performance tab

## 📝 File Structure

```
ui/
├── public/
│   └── index.html              ← Main HTML file
├── src/
│   ├── components/
│   │   ├── Dashboard.js        ← Main layout
│   │   ├── AlertSystem.js      ← Alert & threat level
│   │   ├── NetworkLogs.js      ← Log viewer
│   │   ├── AgentPanels.js      ← Agent cards
│   │   ├── CommunicationToggle.js  ← Toggle switches
│   │   └── AgentDocumentation.js   ← Agent docs
│   ├── styles/                 ← All CSS files
│   ├── App.js                  ← App wrapper
│   └── index.js                ← Entry point
├── package.json                ← Dependencies
└── README.md                   ← Full documentation
```

## 🚀 Next Steps

1. **Customize colors**: Edit preferred colors in `/src/styles/global.css`
2. **Connect to backend**: Replace mock data with real API calls
3. **Add WebSocket**: Real-time updates instead of polling
4. **Deploy**: Run `npm build` and upload to your server

## 💡 Pro Tips

- **Expand all agent cards**: Click each one to see full details
- **Watch the blinking alert**: It blinks more aggressively on critical threats
- **Check network logs**: Scroll through to see threat patterns
- **Read documentation**: Learn what each agent really does
- **Toggle communication**: See how agents work together

## 📞 Support

For issues or questions:
1. Check the full README.md in the ui folder
2. Review component comments in the source code
3. Check browser console (F12 → Console tab) for error messages

---

**Happy defending!** 🛡️ The SwarmShield dashboard is ready to protect your network with style! 🚀
