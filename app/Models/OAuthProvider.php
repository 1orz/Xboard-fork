<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * @property int $id
 * @property string $identifier
 * @property string $name
 * @property string|null $icon
 * @property string $client_id
 * @property string $client_secret
 * @property string $discovery_mode
 * @property string|null $issuer
 * @property string|null $authorization_endpoint
 * @property string|null $token_endpoint
 * @property string|null $userinfo_endpoint
 * @property string|null $jwks_uri
 * @property string $scopes
 * @property string $sub_attribute
 * @property string $email_attribute
 * @property string $name_attribute
 * @property string $email_verified_attribute
 * @property bool $allow_register
 * @property bool $allow_bind
 * @property bool $enable
 * @property int|null $sort
 */
class OAuthProvider extends Model
{
    protected $table = 'v2_oauth_provider';
    protected $dateFormat = 'U';
    protected $guarded = ['id'];
    protected $casts = [
        'created_at' => 'timestamp',
        'updated_at' => 'timestamp',
        'allow_register' => 'boolean',
        'allow_bind' => 'boolean',
        'enable' => 'boolean',
    ];

    public function identities(): HasMany
    {
        return $this->hasMany(UserOAuthIdentity::class, 'provider_id', 'id');
    }
}
