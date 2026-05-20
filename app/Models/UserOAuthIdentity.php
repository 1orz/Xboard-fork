<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property int $id
 * @property int $user_id
 * @property int $provider_id
 * @property string $sub
 * @property string|null $email_snapshot
 * @property string|null $name_snapshot
 * @property array|null $raw_profile
 * @property-read User $user
 * @property-read OAuthProvider $provider
 */
class UserOAuthIdentity extends Model
{
    protected $table = 'v2_user_oauth_identity';
    protected $dateFormat = 'U';
    protected $guarded = ['id'];
    protected $casts = [
        'created_at' => 'timestamp',
        'updated_at' => 'timestamp',
        'raw_profile' => 'array',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'id');
    }

    public function provider(): BelongsTo
    {
        return $this->belongsTo(OAuthProvider::class, 'provider_id', 'id');
    }
}
