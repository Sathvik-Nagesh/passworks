# PassWorks 🔐

A comprehensive, client-side password security toolkit designed for cybersecurity professionals and students. PassWorks provides essential password security tools without requiring any backend infrastructure or external databases.

## ✨ Features

### 🔍 **Password Strength Analyzer**
- **Real-time Analysis**: Instant password strength evaluation as you type
- **Entropy Calculation**: Precise entropy calculation for accurate security assessment
- **Security Checks**: Comprehensive validation including length, character variety, and pattern detection
- **Crack Time Estimation**: Realistic time-to-crack estimates based on current computing power
- **Visual Feedback**: Color-coded strength meter and detailed security recommendations

### 🔑 **Secure Password Generator**
- **Multiple Modes**: Random, Passphrase (Diceware), Pronounceable, and Template patterns
- **Customizable Length**: Generate passwords from 8 to 128 characters
- **Character Set Control**: Choose from uppercase, lowercase, numbers, and symbols
- **Advanced Options**: Exclude similar characters (0O1lI) and ambiguous characters
- **Enforcement Rules**: Require at least one of each selected set, avoid runs/sequences
- **Real-time Stats**: Live entropy and strength calculation for generated passwords
- **One-Click Copy**: Easy copying to clipboard with visual feedback

### 🛡️ **Password Breach Checker**
- **HaveIBeenPwned Integration**: Check passwords against known data breaches
- **Privacy-First**: Only first 5 characters of SHA-1 hash sent to API
- **Local Processing**: Full password never leaves your device
- **Breach Count**: Shows how many times a password has been found in breaches
- **Educational**: Explains the security checking process

### 💾 **Local Password Manager**
- **Client-Side Storage**: All data stored locally in browser
- **Encrypted Storage**: Passwords encrypted using base64 encoding
- **Import/Export**: Backup and restore password databases
- **Secure Display**: Passwords hidden by default with toggle visibility
- **Organized Storage**: Store site names, usernames, passwords, and notes

## 🚀 Getting Started

### Prerequisites
- Modern web browser with JavaScript enabled
- No server or database required - runs entirely client-side

### Installation

1. **Clone or Download**:
   ```bash
   git clone https://github.com/Sathvik-Nagesh/passworks.git
   cd passworks
   ```

2. **Open in Browser**:
   - Simply open `index.html` in any modern web browser
   - No build process or installation required

3. **Start Using**:
   - Navigate between different tools using the tab navigation
   - All features work immediately without any setup

## 🎯 Usage Guide

### Password Strength Analyzer
1. Click on the "Strength Analyzer" tab
2. Enter your password in the input field
3. View real-time analysis including:
   - Entropy score and strength level
   - Character count and crack time estimation
   - Security check results
4. Use the eye icon to toggle password visibility

### Password Generator
1. Navigate to the "Generator" tab
2. Select generation mode:
   - **Random**: Classic character-based generation
   - **Passphrase**: Diceware-style word combinations
   - **Pronounceable**: Syllable-based passwords
   - **Template**: Pattern-based generation (Cvcv-####)
3. Adjust password length using the slider (8-128 characters)
4. Select desired character types:
   - Uppercase letters (A-Z)
   - Lowercase letters (a-z)
   - Numbers (0-9)
   - Special symbols (!@#$%^&*)
5. Choose advanced options:
   - Exclude similar characters
   - Exclude ambiguous characters
   - Require at least one of each selected set
   - Avoid runs and sequences
6. Click "Generate New" to create a password
7. Use "Copy" button to copy to clipboard

### Breach Checker
1. Go to the "Breach Checker" tab
2. Enter the password you want to check
3. Click "Check Breach" to analyze against known breaches
4. View results showing if the password has been compromised
5. See breach count if password was found in data breaches

### Password Manager
1. Access the "Password Manager" tab
2. Click "Add New Password" to store credentials
3. Fill in required information:
   - Site/Service name
   - Username/Email
   - Password
   - Optional notes
4. Use action buttons to:
   - Show/hide passwords
   - Copy passwords to clipboard
   - Delete stored passwords
5. Export/Import for backup and migration

### Settings
1. Navigate to the "Settings" tab
2. Configure lock timeout for password manager
3. Set default password length for generator
4. Save settings to persist across sessions

## 🛠️ Technical Details

### Security Features
- **Client-Side Only**: No data transmission to external servers
- **Local Storage**: All passwords stored in browser's localStorage
- **Encryption**: Passwords encrypted using base64 encoding
- **Privacy-First**: Breach checking uses only hash prefixes
- **No Tracking**: No analytics or user tracking

### Browser Compatibility
- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+
- Mobile browsers (iOS Safari, Chrome Mobile)

### Dependencies
- **Font Awesome**: Icons and visual elements
- **No External Libraries**: Pure JavaScript implementation
- **Modern Web APIs**: Uses Web Crypto API for hashing

## 📁 Project Structure

```
passworks/
├── index.html          # Main HTML file
├── styles.css          # CSS styles and responsive design
├── script.js           # JavaScript functionality
├── manifest.json       # PWA manifest
├── sw.js              # Service worker
└── README.md          # This documentation
```

## 🔧 Development

### Code Structure
- **Modular Design**: Object-oriented JavaScript with clear separation of concerns
- **Event-Driven**: Uses modern event handling and DOM manipulation
- **Responsive**: Mobile-first design with CSS Grid and Flexbox
- **Accessible**: Proper ARIA labels and keyboard navigation

### Key Components
- `PasswordSecuritySuite` class: Main application controller
- Tab management system for navigation
- Password analysis algorithms
- Cryptographic functions for security
- Local storage management
- UI/UX components and animations
- PWA support with service worker

## 🎨 Design Philosophy

### Dark Theme
- **Minimal Interface**: Clean, uncluttered design
- **High Contrast**: Excellent readability in low-light conditions
- **Professional Look**: Suitable for cybersecurity professionals
- **Green Accents**: Security-focused color scheme

### User Experience
- **Intuitive Navigation**: Clear tab-based interface
- **Real-time Feedback**: Immediate visual responses
- **Mobile Responsive**: Works on all device sizes
- **Accessibility**: Keyboard navigation and screen reader support

## 🔒 Security Considerations

### Data Privacy
- All password analysis happens locally
- No passwords are transmitted to external servers
- Breach checking uses only hash prefixes
- Local storage is encrypted

### Best Practices
- Use strong, unique passwords for each account
- Regularly check passwords against breaches
- Enable two-factor authentication where possible
- Keep password manager data backed up

## 🚀 Future Enhancements

### Planned Features
- **AES Encryption**: Upgrade from base64 to proper AES encryption
- **Password History**: Track password changes over time
- **Security Reports**: Generate comprehensive security assessments
- **Dark Web Monitoring**: Enhanced breach detection
- **Team Sharing**: Secure password sharing for teams
- **Biometric Support**: Fingerprint/face ID integration

### Educational Features
- **Security Tips**: Daily cybersecurity recommendations
- **Threat Intelligence**: Latest security news and alerts
- **Training Modules**: Interactive security education
- **Compliance Tools**: Help with security standards

## 🤝 Contributing

Contributions are welcome! This project is perfect for:
- Cybersecurity students learning about password security
- Developers wanting to understand client-side security
- Security professionals building educational tools

### How to Contribute
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🎓 Educational Value

Perfect for BCA students and cybersecurity enthusiasts:
- **Hands-on Learning**: Practical experience with security concepts
- **Real-world Tools**: Industry-standard security practices
- **Portfolio Project**: Great addition to your GitHub profile
- **Interview Prep**: Demonstrates security knowledge and coding skills

## 📞 Support

For questions, issues, or contributions:
- Open an issue on GitHub
- Check the documentation
- Review the code comments

## 🌟 Acknowledgments

- **HaveIBeenPwned**: For providing the breach checking API
- **Font Awesome**: For the beautiful icons
- **Cybersecurity Community**: For inspiration and best practices

---

**Built with ❤️ for the cybersecurity community**

*Keep your passwords secure, your data private, and your GitHub green!* 🚀

---

**PassWorks** - Professional password security toolkit for the modern cybersecurity professional.
