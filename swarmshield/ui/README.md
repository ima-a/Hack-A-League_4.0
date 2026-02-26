# SwarmShield UI - Complete Prototype Dashboard

A **stunning, real-time cybersecurity monitoring dashboard** for the SwarmShield autonomous defense system. Built with React, Framer Motion, and modern Web technologies with a sleek **black, white, and red** aesthetic.

## 🎯 Features

### Core Components

1. **🔴 Alert System**
   - Real-time threat level indicator (Critical, Medium, Normal)
   - **Blinking alert button** with dynamic animations
   - Live threat statistics and response rates
   - Pulsing visual feedback based on threat level

2. **🔍 Network Logs**
   - Real-time log streaming with automatic generation
   - Columns: Time, Source IP, Destination, Threat Type, Severity, Packets, Status
   - Color-coded severity levels (Red, Orange, Yellow, Green)
   - Auto-scrolling with maximized visibility
   - Clear logs functionality

3. **🤖 Agent Panels** (Expandable/Collapsible)
   - **Scout 🔭** - Network threat detection & classification
   - **Analyzer 🧬** - Threat correlation & attack graph analysis
   - **Responder ⚡** - Active defense & response execution
   - **Evolver (Mahoraga) 🔮** - Adaptive defense strategy evolution

   Each panel shows:
   - 💭 Agent thinking process (animated)
   - 📊 Key metrics (detections, confidence, correlations, etc.)
   - 💡 Current insights and findings
   - 🔗 Communication status with next agent

4. **🔗 Communication Control Panel**
   - Toggle switches for agent-to-agent connections:
     - Scout → Analyzer
     - Analyzer → Responder
     - Responder → Evolver
     - Evolver → Scout
     - All Agents Synchronized (consensus mode)
   - Active connection counter
   - Network health status

5. **📚 Agent Documentation**
   - Comprehensive breakdown of each agent
   - Agent responsibilities and capabilities
   - Detection/analysis methods
   - Key performance metrics
   - Workflow visualization
   - **Special Mahoraga reference** with GIF placeholder
   - Tabbed interface for easy switching between agents

## 📁 Project Structure

```
swarmshield/
├── ui/
│   ├── package.json                 # Project dependencies
│   ├── public/
│   │   └── index.html              # Main HTML entry point
│   ├── src/
│   │   ├── index.js                # React root entry
│   │   ├── App.js                  # Main application component
│   │   ├── components/
│   │   │   ├── Navigation.js       # Top navigation bar
│   │   │   ├── Dashboard.js        # Main dashboard layout
│   │   │   ├── AlertSystem.js      # Threat alert display
│   │   │   ├── NetworkLogs.js      # Network log viewer
│   │   │   ├── AgentPanels.js      # Agent insight cards
│   │   │   ├── CommunicationToggle.js  # Agent communication control
│   │   │   └── AgentDocumentation.js   # Complete agent docs
│   │   └── styles/
│   │       ├── global.css          # Global styles & reset
│   │       ├── App.css             # App container styles
│   │       ├── Navigation.css      # Navigation styling
│   │       ├── Dashboard.css       # Dashboard grid layout
│   │       ├── AlertSystem.css     # Alert component styles
│   │       ├── NetworkLogs.css     # Network logs styling
│   │       ├── AgentPanels.css     # Agent cards styling
│   │       ├── CommunicationToggle.css  # Toggle styling
│   │       └── AgentDocumentation.css   # Documentation styles
│   └── README.md                   # This file
```

## 🚀 Quick Start

### Prerequisites
- Node.js 14+ or higher
- npm or yarn package manager

### Installation & Setup

```bash
# Navigate to the UI directory
cd swarmshield/ui

# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm build
```

The application will start at `http://localhost:3000` with hot-reload enabled.

## 🎨 Design System

### Color Palette
- **Primary Red**: `#ff1744` - Alerts, critical elements
- **Secondary Red**: `#ff5252` - Hover states, emphasis
- **Background Black**: `#0a0e27` - Primary background
- **Dark Navy**: `#1a1f3a` - Secondary background
- **White**: `#ffffff` - Text and accents
- **Accent Cyan**: `#00bcd4` - Scout agent color
- **Accent Purple**: `#9c27b0` - Analyzer agent color
- **Accent Orange**: `#ff5722` - Responder agent color
- **Accent Red**: `#f44336` - Evolver/Mahoraga agent color

### Typography
- **Font**: Inter, system UI fonts
- **Headings**: 600 weight, letter-spacing -0.5px
- **Body**: 400-500 weight, 0.95rem base size
- **Monospace**: Courier New for IP addresses and technical data

### Animations
- **Framer Motion** for smooth, performant animations
- **Pulsing effects** for alerts and status indicators
- **Scale & slide transitions** for expandable panels
- **Gradient animations** for visual feedback

## 🔄 Agent Architecture

### Scout 🔭 - Network Threat Detection
- Detects DDoS attacks via statistical anomaly detection
- Identifies port scans using entropy analysis
- Flags data exfiltration patterns
- Uses Monte Carlo simulation for threat classification
- Confidence-based threat reporting

### Analyzer 🧬 - Threat Correlation
- Correlates threats from Scout across network
- Builds attack graphs showing threat relationships
- Calculates lateral movement risk
- Simulates propagation probability
- Generates recommended defensive actions

### Responder ⚡ - Active Defense
- Executes blocking actions on malicious IPs
- Redirects suspicious traffic to honeypots
- Handles rate limiting on attack vectors
- Logs all defensive actions in real-time
- Auto-unblock scheduling for temporary blocks

### Evolver 🔮 (Mahoraga) - Adaptive Strategy
- Uses genetic algorithms to evolve detection thresholds
- Adapts to new attack patterns continuously
- Minimizes false positives (2× penalty) and false negatives
- LLM-enhanced strategy assessment
- Supplies optimized thresholds back to Scout

## 📊 Real-Time Data Flow

```
Scout Detection
    ↓
Analyzer Correlation
    ↓
Responder Action
    ↓
Evolver Learning
    ↓
Scout Adaptation
```

## 🎭 Component States

### Alert System States
- **🟢 Normal** - Green indicator, "All systems normal"
- **🟡 Medium** - Orange indicator, animated warning
- **🔴 Critical** - Red indicator, **blinking button**, aggressive animation

### Agent Panel States
- **Collapsed** - Shows title, status, and icon
- **Expanded** - Full details: thinking process, metrics, insights, communication status

### Log States
- **Streaming** - New logs appear at top, old ones pushed down
- **Empty** - "No threats detected" message
- **Paused** - User can clear history

## 🔌 Backend Integration

The UI is designed to connect with the SwarmShield backend REST APIs:

```javascript
// Example API endpoints to implement
GET    /api/agents/status         // Agent status & metrics
GET    /api/logs/network          // Network logs
GET    /api/communications        // Agent connections
POST   /api/communications/toggle // Toggle connections
GET    /api/threat-classification // Scout data
GET    /api/correlations          // Analyzer data
GET    /api/actions               // Responder data
GET    /api/evolution             // Evolver data
```

## 📦 Dependencies

- **react** (18.2.0) - UI framework
- **react-dom** (18.2.0) - React DOM rendering
- **framer-motion** (10.16.4) - Animation library
- **react-icons** (4.11.0) - Icon library
- **axios** (1.6.0) - HTTP client

## 🎬 Agent Documentation Features

### Scout Documentation
- ✅ Detection methods (Monte Carlo, entropy analysis)
- ✅ Threat types monitored
- ✅ Key performance metrics
- ✅ Statistical anomaly detection process

### Analyzer Documentation
- ✅ Threat correlation rules
- ✅ Attack graph construction
- ✅ Risk assessment methodology
- ✅ Propagation simulation

### Responder Documentation
- ✅ Action types (block, rate limit, redirect)
- ✅ Honeypot engagement strategy
- ✅ Auto-unblock scheduling
- ✅ Real-time action logging

### Evolver Documentation
- ✅ Genetic algorithm process
- ✅ Gene evolution parameters
- ✅ Fitness function explanation
- ✅ 🎬 **Mahoraga adaptation GIF**

![Mahoraga (Evolver) adapting](../../mahoraga-mahora-ga.gif)

## 🎨 Visual Highlights

### Gradient Backgrounds
- Dynamic gradients with radial circles
- Color-coded agent panels
- Smooth transitions between themes

### Animated Elements
- Blinking alert button (critical state)
- Pulsing status indicators
- Animated metric counters
- Expanding/collapsing panels
- Smooth log streaming

### Interactive Elements
- Hover effects on all clickable components
- Toggle switches with smooth animations
- Tab-based navigation for documentation
- Expandable agent cards with smooth transitions

## 📱 Responsive Design

The dashboard is fully responsive:
- **Desktop** (1200px+): Full 4-column grid for agent panels
- **Tablet** (768px-1199px): 2-column agent grid
- **Mobile** (< 768px): Single-column responsive layout

## 🔧 Development Tips

### Adding New Features
1. Create a new component in `src/components/`
2. Import and use Framer Motion for animations
3. Add corresponding styles in `src/styles/`
4. Import component in Dashboard.js

### Customizing Colors
Edit `src/styles/global.css` and update CSS variables:
```css
:root {
  --primary-red: #ff1744;
  --secondary-red: #ff5252;
  --bg-dark: #0a0e27;
  /* ... */
}
```

### Extending Agent Documentation
Edit `AgentDocumentation.js` agents array to add:
- New metadata fields
- Custom section layouts
- Additional metrics
- Reference images/GIFs

## 🚀 Production Deployment

```bash
# Build optimized production bundle
npm run build

# Serve with a simple HTTP server
npx serve -s build

# Or deploy to your hosting platform
# - Vercel: npm install -g vercel && vercel
# - Netlify: netlify deploy --prod --dir=build
# - GitHub Pages: Follow standard deployment
```

## 📈 Performance

- **Optimized re-renders** through React.memo and useMemo
- **Lazy animations** with Framer Motion
- **CSS-in-JS** with minimal bundle size
- **Responsive images** and SVG icons
- **Smooth scroll** with custom scrollbar styling

## 🐛 Troubleshooting

### Port 3000 Already in Use?
```bash
PORT=3001 npm start
```

### Module Not Found?
```bash
rm -rf node_modules package-lock.json
npm install
```

### Slow Performance?
- Check browser DevTools Performance tab
- Reduce animation complexity in low-end devices
- Enable production build optimizations

## 📚 Documentation References

- [React Docs](https://react.dev)
- [Framer Motion Guide](https://www.framer.com/motion/)
- [React Icons Collection](https://react-icons.github.io/react-icons/)

## 🎓 Next Steps

1. **Backend Integration**: Connect to SwarmShield REST APIs
2. **Real Data**: Replace mock data with actual agent metrics
3. **WebSocket**: Implement live updates for logs and alerts
4. **Persistence**: Add localStorage for user preferences
5. **Dark/Light Mode**: Extend theme system
6. **Multi-language**: Add i18n support

## 📝 License

Part of the SwarmShield Cybersecurity Defense System.

---

**Have questions?** Check the agent documentation tabs in the UI or review the component code comments in `/src/components/`.

**Looking to customize?** Start with editing the agent data in `Dashboard.js` or styling in the CSS files.

Happy defending! 🛡️
