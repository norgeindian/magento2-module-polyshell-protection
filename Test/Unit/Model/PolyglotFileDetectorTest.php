<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Model;

use Magento\Framework\Exception\InputException;
use Aregowe\PolyShellProtection\Model\PolyglotFileDetector;
use PHPUnit\Framework\TestCase;

class PolyglotFileDetectorTest extends TestCase
{
    private PolyglotFileDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new PolyglotFileDetector();
    }

    /**
     * Test that legitimate PNG files pass validation.
     */
    public function testLegitimatePngPasses(): void
    {
        $pngFile = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');
        $this->detector->assertNotPolyglot($pngFile, 'test.png');
        $this->assertTrue(true); // No exception thrown
    }

    /**
     * Test that GIF89a with embedded PHP fails validation.
     */
    public function testPolyglotGifWithPhpFails(): void
    {
        // Payload is split via concatenation so external malware scanners
        // (e.g. Sansec eComscan) do not flag this test fixture as a real
        // backdoor. Runtime semantics of the assembled payload are unchanged.
        // See issue #12.
        $polyglotPayload = 'GIF89a;<' . '?' . 'php echo 409723*20; if(md5('
            . '$' . '_COOKIE["d"])=="a17028468cb2a870d460676d6d6da3ad63706778e3")'
            . '{' . 'eval' . '(' . 'base64_decode' . '($' . '_REQUEST["id"]));} ?>';

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file contains executable code');
        
        $this->detector->assertNotPolyglot($polyglotPayload, 'index.php');
    }

    /**
     * Test that executable-code detection returns a generic user-facing message.
     */
    public function testPolyglotGifWithPhpReturnsGenericTranslatableMessage(): void
    {
        // Split to avoid malware-scanner false positives. See issue #12.
        $polyglotPayload = 'GIF89a;<' . '?' . 'php ' . 'system' . '(' . '$' . "_GET['cmd']); ?>";

        $this->expectException(InputException::class);
        $this->expectExceptionMessage(
            'Uploaded file contains executable code and is not permitted for security reasons.'
        );

        $this->detector->assertNotPolyglot($polyglotPayload, 'shell.gif');
    }

    /**
     * Test that known beacon pattern is detected.
     * Payload uses the beacon value without PHP tags so that the
     * ATTACK_SIGNATURES check fires before PHP_CODE_PATTERNS.
     */
    public function testBeaconSignatureDetected(): void
    {
        $beaconPayload = "GIF89a" . str_repeat("\x00", 100) . "echo 409723*20;";

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('matches known malicious payload signature');

        $this->detector->assertNotPolyglot($beaconPayload, 'accesson.php');
    }

    /**
     * Test that known attack hash is detected.
     */
    public function testAttackHashDetected(): void
    {
        $attackPayload = "GIF89a" . "a17028468cb2a870d460676d6d6da3ad63706778e3";
        
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('matches known malicious payload signature');
        
        $this->detector->assertNotPolyglot($attackPayload, 'shell.gif');
    }

    /**
     * Test that base64_decode pattern is detected.
     */
    public function testBase64DecodePatternDetected(): void
    {
        // Split to avoid malware-scanner false positives. See issue #12.
        $payload = 'GIF87a' . 'eval' . '(' . 'base64_decode' . '($' . "_REQUEST['cmd']))";

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file contains executable code');
        
        $this->detector->assertNotPolyglot($payload, 'shell.gif');
    }

    /**
     * Test that socket operations are detected.
     * PNG signature must include the leading \x89 byte.
     */
    public function testSocketCreationDetected(): void
    {
        $payload = "\x89PNG\r\n\x1a\n" . "\$sock = fsockopen(\$host, 80); socket_create();";

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file contains executable code');

        $this->detector->assertNotPolyglot($payload, 'reverse.png');
    }

    /**
     * Issue #17: short byte sequences that look like deprecated PHP
     * patterns (e.g. '/e"') can appear naturally in compressed JPEG/PNG
     * entropy and must not flag legitimate images.
     */
    public function testLegitimateImageWithDeprecatedRegexBytesPasses(): void
    {
        $jpegMagic = "\xFF\xD8\xFF\xE0";
        $payload = $jpegMagic . str_repeat("\xAA", 200) . '/e"' . str_repeat("\xBB", 200);

        $this->detector->assertNotPolyglot($payload, 'photo.jpg');
        $this->assertTrue(true);
    }

    /**
     * Issue #17: null bytes between characters must not be collapsed
     * before pattern matching. PHP cannot execute code split by null
     * bytes, so a sequence like < \x00 ? \x00 = is not a real open
     * tag and must not be flagged as one.
     */
    public function testJpegWithNullSeparatedPhpTagBytesPasses(): void
    {
        $jpegMagic = "\xFF\xD8\xFF\xE0";
        $payload = $jpegMagic . str_repeat("\xAA", 50) . "<\x00?\x00=" . str_repeat("\xBB", 50);

        $this->detector->assertNotPolyglot($payload, 'fragmented.jpg');
        $this->assertTrue(true);
    }

    /**
     * Issue #17: the short-echo tag '<?=' is only three bytes, so the bare
     * sequence turns up in compressed JPEG/PNG entropy and used to flag
     * legitimate images. It must only be treated as code when it actually
     * opens a PHP expression, so '<?=' followed by a random byte (or a stray
     * letter) has to pass.
     */
    public function testLegitimateImageWithShortEchoBytesInEntropyPasses(): void
    {
        $jpegMagic = "\xFF\xD8\xFF\xE0";
        $nonAscii = $jpegMagic . str_repeat("\xAA", 200) . '<' . '?' . '=' . "\xBD\xB4" . str_repeat("\xCC", 200);
        $letter = $jpegMagic . str_repeat("\xAA", 200) . '<' . '?' . '=' . 'N' . str_repeat("\xCC", 200);

        $this->detector->assertNotPolyglot($nonAscii, 'photo-a.jpg');
        $this->detector->assertNotPolyglot($letter, 'photo-b.jpg');
        $this->assertTrue(true);
    }

    /**
     * Issue #17: a real short-echo polyglot ('<?=' followed by whitespace,
     * '$', '(', a backtick or '@') must still be caught. Here the tag is the
     * only trigger, so this proves the refined match, not another pattern.
     */
    public function testPolyglotWithShortEchoTagFails(): void
    {
        // Split to avoid malware-scanner false positives. See issue #12.
        $payload = 'GIF89a;<' . '?' . '= ' . 'phpinfo' . '()' . ' ?>';

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file contains executable code');

        $this->detector->assertNotPolyglot($payload, 'shortecho.gif');
    }

    /**
     * Issue #17: '<?=`cmd`' runs a shell command through PHP's backtick
     * operator with no function name, so no other pattern in the list would
     * catch it. The refined short-echo match has to.
     */
    public function testPolyglotWithShortEchoBacktickShellExecFails(): void
    {
        // Split to avoid malware-scanner false positives. See issue #12.
        $payload = 'GIF89a;<' . '?' . '=' . '`' . 'id' . '`' . ' ?>';

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file contains executable code');

        $this->detector->assertNotPolyglot($payload, 'backtick.gif');
    }
}
