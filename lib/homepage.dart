import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:http/http.dart' as http;

class DangerAanalloHomepage extends StatefulWidget {
  const DangerAanalloHomepage({Key? key}) : super(key: key);

  @override
  State<DangerAanalloHomepage> createState() => _DangerAanalloHomepageState();
}

class _DangerAanalloHomepageState extends State<DangerAanalloHomepage>
    with TickerProviderStateMixin {
  final TextEditingController _urlController = TextEditingController();
  bool _isChecking = false;
  String _status = '';
  String _cookieCount = 'Unknown';
  bool _collectsPersonalData = false;
  late AnimationController _pulseController;
  late Animation<double> _pulseAnimation;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      duration: const Duration(seconds: 1),
      vsync: this,
    );
    _pulseAnimation = Tween<double>(begin: 1.0, end: 1.1).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

  Future<void> _checkWebsite() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) return;

    setState(() {
      _isChecking = true;
      _status = '';
    });

    _pulseController.repeat(reverse: true);

    final exists = await _domainExists(url);
    if (!exists) {
      setState(() {
        _status = 'invalid';
        _isChecking = false;
      });
      _pulseController.stop();
      return;
    }

    final isSafe = await _checkGoogleSafeBrowsing(url);
    final ipqData = await _checkIPQuality(url);
    final vtScore = await _checkVirusTotal(url);

    setState(() {
      _status = (!isSafe || vtScore > 3)
          ? 'danger'
          : ipqData['suspicious']
              ? 'suspicious'
              : 'safe';

      _cookieCount = ipqData['cookies']?.toString() ?? 'Unknown';
      _collectsPersonalData = ipqData['tracking'] || ipqData['sensitive'];
      _isChecking = false;
    });
    _pulseController.stop();
  }

  Future<bool> _domainExists(String url) async {
    try {
      Uri uri = Uri.parse(url);
      if (!uri.hasScheme) {
        uri = Uri.parse("https://$url");
      }
      final response = await http.head(uri).timeout(const Duration(seconds: 5));
      return response.statusCode < 500;
    } catch (e) {
      return false;
    }
  }

  Future<bool> _checkGoogleSafeBrowsing(String url) async {
    final apiKey = dotenv.env['GOOGLE_SAFE_BROWSING_API'];
    final body = jsonEncode({
      "client": {"clientId": "danger-aanallo", "clientVersion": "1.0"},
      "threatInfo": {
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [
          {"url": url}
        ]
      }
    });

    final response = await http.post(
      Uri.parse(
          'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$apiKey'),
      headers: {'Content-Type': 'application/json'},
      body: body,
    );

    final data = json.decode(response.body);
    return data.isEmpty;
  }

  Future<Map<String, dynamic>> _checkIPQuality(String url) async {
    final apiKey = dotenv.env['IP_QUALITY_API'];
    final encodedUrl = Uri.encodeComponent(url);
    final response = await http.get(
      Uri.parse('https://ipqualityscore.com/api/json/url/$apiKey/$encodedUrl'),
    );

    final result = json.decode(response.body);
    print("IPQualityScore Result: $result");
    return {
      'suspicious': result['suspicious'] ?? false,
      'cookies': result['domain_rank'] ?? 'Unknown',
      'tracking': result['tracking'] ?? false,
      'sensitive': result['sensitive'] ?? false,
    };
  }

  Future<int> _checkVirusTotal(String url) async {
    final apiKey = dotenv.env['VIRUS_TOTAL_API'];
    final response = await http.post(
      Uri.parse('https://www.virustotal.com/api/v3/urls'),
      headers: {
        'x-apikey': apiKey!,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: {'url': url},
    );

    final data = json.decode(response.body);
    final analysisId = data['data']['id'];

    final report = await http.get(
      Uri.parse('https://www.virustotal.com/api/v3/analyses/$analysisId'),
      headers: {'x-apikey': apiKey},
    );

    final analysis = json.decode(report.body);
    final maliciousCount =
        analysis['data']['attributes']['stats']['malicious'] ?? 0;
    return maliciousCount;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF8FAFC),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [
              Color(0xFFF8FAFC),
              Color(0xFFE2E8F0),
            ],
          ),
        ),
        child: SafeArea(
          child: CustomScrollView(
            slivers: [
              _buildSliverAppBar(),
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.all(24.0),
                  child: Column(
                    children: [
                      _buildHeroSection(),
                      const SizedBox(height: 32),
                      _buildInputSection(),
                      const SizedBox(height: 24),
                      if (_isChecking) _buildLoadingSection(),
                      if (_status.isNotEmpty && !_isChecking) _buildResultSection(),
                      const SizedBox(height: 32),
                      _buildFeaturesGrid(),
                      const SizedBox(height: 24),
                      _buildSecurityTip(),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSliverAppBar() {
    return SliverAppBar(
      expandedHeight: 120,
      floating: false,
      pinned: true,
      elevation: 0,
      backgroundColor: Colors.transparent,
      flexibleSpace: FlexibleSpaceBar(
        background: Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
          ),
          child: SafeArea(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.white.withOpacity(0.2),
                      borderRadius: BorderRadius.circular(16),
                    ),
                    child: const Icon(
                      Icons.security,
                      color: Colors.white,
                      size: 32,
                    ),
                  ),
                  const SizedBox(width: 16),
                  const Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          'Shieldy',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 28,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        Text(
                          'Website Security Scanner',
                          style: TextStyle(
                            color: Colors.white70,
                            fontSize: 16,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildHeroSection() {
    return Container(
      padding: const EdgeInsets.all(32),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.08),
            blurRadius: 24,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: Column(
        children: [
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)],
              ),
              borderRadius: BorderRadius.circular(20),
            ),
            child: const Icon(
              Icons.verified_user_outlined,
              size: 48,
              color: Colors.white,
            ),
          ),
          const SizedBox(height: 24),
          const Text(
            'Advanced Website Security Analysis',
            style: TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.bold,
              color: Color(0xFF1E293B),
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 12),
          Text(
            'Protect yourself from malicious websites, tracking cookies, and data theft with our comprehensive security scanner.',
            style: TextStyle(
              fontSize: 16,
              color: Colors.grey[600],
              height: 1.5,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildInputSection() {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.08),
            blurRadius: 24,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Enter Website URL',
            style: TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.bold,
              color: Color(0xFF1E293B),
            ),
          ),
          const SizedBox(height: 16),
          Container(
            decoration: BoxDecoration(
              color: const Color(0xFFF8FAFC),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: const Color(0xFFE2E8F0)),
            ),
            child: TextField(
              controller: _urlController,
              style: const TextStyle(fontSize: 16),
              decoration: InputDecoration(
                hintText: 'https://example.com',
                hintStyle: TextStyle(color: Colors.grey[500]),
                prefixIcon: Container(
                  margin: const EdgeInsets.all(12),
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: const Color(0xFF6366F1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.language, color: Colors.white, size: 20),
                ),
                border: InputBorder.none,
                contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
              ),
            ),
          ),
          const SizedBox(height: 20),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: _isChecking ? null : _checkWebsite,
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF6366F1),
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(16),
                ),
                elevation: 0,
                shadowColor: Colors.transparent,
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  if (_isChecking)
                    const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                      ),
                    )
                  else
                    const Icon(Icons.security, size: 20),
                  const SizedBox(width: 12),
                  Text(
                    _isChecking ? 'Scanning Website...' : 'Scan Website',
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLoadingSection() {
    return AnimatedBuilder(
      animation: _pulseAnimation,
      builder: (context, child) {
        return Transform.scale(
          scale: _pulseAnimation.value,
          child: Container(
            padding: const EdgeInsets.all(32),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(24),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFF6366F1).withOpacity(0.2),
                  blurRadius: 24,
                  offset: const Offset(0, 8),
                ),
              ],
            ),
            child: Column(
              children: [
                Container(
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)],
                    ),
                    borderRadius: BorderRadius.circular(50),
                  ),
                  child: const CircularProgressIndicator(
                    strokeWidth: 3,
                    valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                  ),
                ),
                const SizedBox(height: 24),
                const Text(
                  'Analyzing Website Security',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Color(0xFF1E293B),
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'Running comprehensive security checks...',
                  style: TextStyle(
                    color: Colors.grey[600],
                    fontSize: 16,
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildResultSection() {
    IconData icon;
    List<Color> gradientColors;
    String title;
    String message;
    String statusEmoji;

    switch (_status) {
      case 'safe':
        icon = Icons.verified_user;
        gradientColors = [const Color(0xFF10B981), const Color(0xFF059669)];
        title = 'Website is Safe';
        message = 'This website appears to be secure and trustworthy.';
        statusEmoji = '✅';
        break;
      case 'suspicious':
        icon = Icons.warning_amber;
        gradientColors = [const Color(0xFFF59E0B), const Color(0xFFD97706)];
        title = 'Potentially Suspicious';
        message = 'Exercise caution when browsing this website.';
        statusEmoji = '⚠️';
        break;
      case 'invalid':
        icon = Icons.error_outline;
        gradientColors = [const Color(0xFF6B7280), const Color(0xFF4B5563)];
        title = 'Website Not Found';
        message = 'This website does not exist or is currently unreachable.';
        statusEmoji = '🔍';
        break;
      default:
        icon = Icons.dangerous;
        gradientColors = [const Color(0xFFEF4444), const Color(0xFFDC2626)];
        title = 'Dangerous Website';
        message = 'This website may pose security risks. Avoid visiting.';
        statusEmoji = '🚨';
    }

    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
        boxShadow: [
          BoxShadow(
            color: gradientColors[0].withOpacity(0.2),
            blurRadius: 24,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: Column(
        children: [
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              gradient: LinearGradient(colors: gradientColors),
              borderRadius: BorderRadius.circular(20),
            ),
            child: Icon(icon, size: 48, color: Colors.white),
          ),
          const SizedBox(height: 20),
          Text(
            '$statusEmoji $title',
            style: TextStyle(
              fontSize: 22,
              fontWeight: FontWeight.bold,
              color: gradientColors[1],
            ),
          ),
          const SizedBox(height: 8),
          Text(
            message,
            style: TextStyle(
              color: Colors.grey[600],
              fontSize: 16,
              height: 1.4,
            ),
            textAlign: TextAlign.center,
          ),
          if (_status != 'invalid') ...[
            const SizedBox(height: 24),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFFF8FAFC),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                children: [
                  _buildDetailRow('🍪 Cookies Detected', _cookieCount),
                  const SizedBox(height: 12),
                  _buildDetailRow(
                    'Personal Data Collection',
                    _collectsPersonalData ? 'Detected' : 'Not Detected',
                    isWarning: _collectsPersonalData,
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            _buildDangerMeter(),
          ],
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value, {bool isWarning = false}) {
    return Row(
      children: [
        Expanded(
          child: Text(
            label,
            style: const TextStyle(
              fontWeight: FontWeight.w500,
              color: Color(0xFF374151),
            ),
          ),
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          decoration: BoxDecoration(
            color: isWarning ? const Color(0xFFFEF3C7) : const Color(0xFFDCFCE7),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Text(
            value,
            style: TextStyle(
              fontWeight: FontWeight.w600,
              color: isWarning ? const Color(0xFFD97706) : const Color(0xFF059669),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildDangerMeter() {
    double progress;
    List<Color> colors;

    switch (_status) {
      case 'safe':
        progress = 0.2;
        colors = [const Color(0xFF10B981), const Color(0xFF059669)];
        break;
      case 'suspicious':
        progress = 0.6;
        colors = [const Color(0xFFF59E0B), const Color(0xFFD97706)];
        break;
      case 'danger':
        progress = 0.9;
        colors = [const Color(0xFFEF4444), const Color(0xFFDC2626)];
        break;
      default:
        progress = 0.0;
        colors = [const Color(0xFF6B7280), const Color(0xFF4B5563)];
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Risk Level',
          style: TextStyle(
            fontWeight: FontWeight.w600,
            color: Color(0xFF374151),
          ),
        ),
        const SizedBox(height: 8),
        Container(
          height: 8,
          decoration: BoxDecoration(
            color: const Color(0xFFE5E7EB),
            borderRadius: BorderRadius.circular(4),
          ),
          child: FractionallySizedBox(
            alignment: Alignment.centerLeft,
            widthFactor: progress,
            child: Container(
              decoration: BoxDecoration(
                gradient: LinearGradient(colors: colors),
                borderRadius: BorderRadius.circular(4),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildFeaturesGrid() {
    final features = [
      {
        'icon': Icons.shield_outlined,
        'title': 'Malware Detection',
        'description': 'Scans for malicious software and threats',
        'color': const Color(0xFF3B82F6),
      },
      {
        'icon': Icons.cookie_outlined,
        'title': 'Cookie Analysis',
        'description': 'Analyzes tracking cookies and privacy risks',
        'color': const Color(0xFF8B5CF6),
      },
      {
        'icon': Icons.privacy_tip_outlined,
        'title': 'Privacy Protection',
        'description': 'Identifies data collection practices',
        'color': const Color(0xFF10B981),
      },
      {
        'icon': Icons.speed_outlined,
        'title': 'Real-time Scanning',
        'description': 'Instant security assessment results',
        'color': const Color(0xFFF59E0B),
      },
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Security Features',
          style: TextStyle(
            fontSize: 22,
            fontWeight: FontWeight.bold,
            color: Color(0xFF1E293B),
          ),
        ),
        const SizedBox(height: 16),
        GridView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 2,
            crossAxisSpacing: 16,
            mainAxisSpacing: 16,
            childAspectRatio: 0.95,
          ),
          itemCount: features.length,
          itemBuilder: (context, index) {
            final feature = features[index];
            return Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(20),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.06),
                    blurRadius: 16,
                    offset: const Offset(0, 4),
                  ),
                ],
              ),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: (feature['color'] as Color).withOpacity(0.1),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Icon(
                      feature['icon'] as IconData,
                      size: 28,
                      color: feature['color'] as Color,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    feature['title'] as String,
                    style: const TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.bold,
                      color: Color(0xFF1E293B),
                    ),
                    textAlign: TextAlign.center,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 6),
                  Expanded(
                    child: Text(
                      feature['description'] as String,
                      style: TextStyle(
                        fontSize: 11,
                        color: Colors.grey[600],
                        height: 1.2,
                      ),
                      textAlign: TextAlign.center,
                      maxLines: 3,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ],
    );
  }

  Widget _buildSecurityTip() {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(24),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.lightbulb_outline, color: Colors.white, size: 28),
              SizedBox(width: 12),
              Text(
                'Security Tip',
                style: TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          const Text(
            'Always verify website URLs before entering personal information. Look for HTTPS and check for suspicious redirects.',
            style: TextStyle(
              fontSize: 16,
              color: Colors.white,
              height: 1.5,
            ),
          ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.2),
              borderRadius: BorderRadius.circular(16),
            ),
            child: const Text(
              '💡 "Browseril vandi poyalum, njan back seat-il und 👀"',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w600,
                color: Colors.white,
                fontStyle: FontStyle.italic,
              ),
            ),
          ),
        ],
      ),
    );
  }
}