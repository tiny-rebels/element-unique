<?php

namespace Element\Unique;

use Element\Unique\Helpers\SoftwareLicense;

class Generate {

    /**
     * Generate params
     */
    protected int $length       = 12;                                   // Default length
    protected string $baseChars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';   // Setting the allowed characters to be used
    protected string $format    = '4444';                               // Characters in each segment, max 5 segments
    protected string $prefix    = '';                                   // Specify if the uuid should have a prefix attached to it in the front?
    protected string $name      = '';                                   // Name of the person or company in which the key is generated for?
    protected string $software  = '';                                   // Name of the software in which the key is generated for?

    /**
     * Generate constructor.
     *
     * @param SoftwareLicense $softwareLicense
     */
    public function __construct(SoftwareLicense $softwareLicense) {

        $this->softwareLicense = $softwareLicense;
    }

    /**
     * @return array
     */
    public function authRecoveryTokens() {

        $tokens = [];

        for ($key = 0 ; $key < 10; $key++) {

            $tokens[] = strtolower($this->softwareLicense(10, 55, '', ''));
        }

        return $tokens;
    }

    /**
     * @return string
     */
    public function otp() {

        $result = rand(100,999) . '-' . rand(100,999);

        return $result;
    }

    /**
     * @param $length
     * @param $format
     * @param $name
     * @param $software
     *
     * @return string
     */
    public function softwareLicense($length, $format, $name, $software) {

        $keylength  = $length ?? $this->length;
        $keyformat  = $format ?? $this->format;
        $name       = $name ?? $this->name;
        $software   = $software ?? $this->software;

        $initlength = $this->softwareLicense->initLen($keylength);
        $initcode   = $this->softwareLicense->initCode($initlength, $this->baseChars);
        $fullcode   = $this->softwareLicense->extendCode($initcode, $software, $name, $keylength);

        return $this->softwareLicense->formatLicense($fullcode, $keyformat, $keylength);
    }

    /**
     * @param $security_level
     *
     * @return false|string
     */
    public function token($security_level) {

        $security   = $security_level ?? PASSWORD_DEFAULT;

        $result = password_hash(uniqid(), $security);

        return $result;
    }

    /**
     * @param $prefix
     * @param $entropy
     *
     * @return string
     */
    public function uid($prefix, $entropy) {

        $prefix     = $prefix ?? $this->prefix;
        $entropy    = $entropy ?? false;

        $result     = uniqid($prefix, $entropy);

        return $result;
    }

}