<?php

namespace App\Library;

class Totp {

    protected static $code_length = 6;
    protected static $clock_tolerant = 1;

    protected static function base32_lookup_table() {
        return array(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '='  // padding char
        );
    }

    /**
     * Create new secret.
     * 16 characters, randomly chosen from the allowed base32 characters.
     *
     * @param int $totp_token_length
     * @return string
     */
    public static function create_totp_token($totp_token_length = 16) {
        $valid_chars = self::base32_lookup_table();
        unset($valid_chars[32]);

        $totp_token = '';
        for ($i = 0; $i < $totp_token_length; $i++) {
            $totp_token .= $valid_chars[array_rand($valid_chars)];
        }
        return $totp_token;
    }

    /**
     * Calculate the code, with given secret and point in time
     *
     * @param string $totp_token
     * @param int|null $time_slice
     * @return string
     */
    public static function gen_verification_code($totp_token, $time_slice = null) {
        if ($time_slice === null) {
            $time_slice = floor(time() / 30);
        }

        $totp_token = self::base32_decode($totp_token);

        // Pack time into binary string
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $time_slice);
        // Hash it with users secret key
        $hash = hash_hmac('SHA1', $time, $totp_token, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hash, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = substr($hash, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        $modulo = pow(10, self::$code_length);

        return str_pad($value % $modulo, self::$code_length, '0', STR_PAD_LEFT);
    }

    /**
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
     *
     * @param string $totp_token
     * @param string $auth_code
     * @param int  $clock_tolerant This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
     * @param int|null $time_slice time slice if we want use other that time()
     * @return bool
     */
    public static function verify_verification_code($totp_token, $verification_code, $time_slice = null) {
        if ($time_slice === null) {
            $time_slice = floor(time() / 30);
        }

        for ($i = -self::$clock_tolerant; $i <= self::$clock_tolerant; $i++) {
            $calculated_code = self::gen_verification_code($totp_token, $time_slice + $i);

            if ($calculated_code == $verification_code) {
                return true;
            }
        }
        return false;
    }

    /**
     * Set the code length, should be >=6
     *
     * @param int $length
     * @return GoogleAuthenticator
     */
    public static function setCodeLength($length) {
        self::$code_length = $length;
        return self::$code_length;
    }

    /**
     * Helper class to decode base32
     *
     * @param $totp_token
     * @return bool|string
     */
    protected static function base32_decode($totp_token) {
        if (empty($totp_token))
            return '';

        $base32chars = self::base32_lookup_table();
        $base32chars_flipped = array_flip($base32chars);

        $padding_count = substr_count($totp_token, $base32chars[32]);
        $allowed_values = array(6, 4, 3, 1, 0);
        if (!in_array($padding_count, $allowed_values))
            return false;
        for ($i = 0; $i < 4; $i++) {
            if ($padding_count == $allowed_values[$i] &&
                    substr($totp_token, -($allowed_values[$i])) != str_repeat($base32chars[32], $allowed_values[$i]))
                return false;
        }
        $totp_token = str_replace('=', '', $totp_token);
        $totp_token = str_split($totp_token);
        $binary_string = "";
        for ($i = 0; $i < count($totp_token); $i = $i + 8) {
            $x = "";
            if (!in_array($totp_token[$i], $base32chars))
                return false;
            for ($j = 0; $j < 8; $j++) {
                $x .= str_pad(base_convert(@$base32chars_flipped[@$totp_token[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eight_bits = str_split($x, 8);
            for ($z = 0; $z < count($eight_bits); $z++) {
                $binary_string .= ( ($y = chr(base_convert($eight_bits[$z], 2, 10))) || ord($y) == 48 ) ? $y : "";
            }
        }
        return $binary_string;
    }

    /**
     * Helper class to encode base32
     *
     * @param string $secret
     * @param bool $padding
     * @return string
     */
    protected static function base32_encode($totp_token, $padding = true) {
        if (empty($totp_token))
            return '';

        $base32chars = self::base32_lookup_table();

        $totp_token = str_split($totp_token);
        $binary_string = "";
        for ($i = 0; $i < count($totp_token); $i++) {
            $binary_string .= str_pad(base_convert(ord($totp_token[$i]), 10, 2), 8, '0', STR_PAD_LEFT);
        }
        $five_bits = str_split($binary_string, 5);
        $base32 = "";
        $i = 0;
        while ($i < count($five_bits)) {
            $base32 .= $base32chars[base_convert(str_pad($five_bits[$i], 5, '0'), 2, 10)];
            $i++;
        }
        if ($padding && ($x = strlen($binary_string) % 40) != 0) {
            if ($x == 8)
                $base32 .= str_repeat($base32chars[32], 6);
            elseif ($x == 16)
                $base32 .= str_repeat($base32chars[32], 4);
            elseif ($x == 24)
                $base32 .= str_repeat($base32chars[32], 3);
            elseif ($x == 32)
                $base32 .= $base32chars[32];
        }
        return $base32;
    }

    /**
     * Get QR-Code URL for image, from google charts
     * @param string $login_id
     * @param string $totp_token
     * @param string $title
     * @return string
     */
    public static function gen_totp_token_qrcode_url($totp_token, $app_name, $id) {
        $totp_qrcode_url = 'otpauth://totp/' . $app_name . '?secret=' . $totp_token . '&issuer=' . $id;
        return $totp_qrcode_url;
    }

}
