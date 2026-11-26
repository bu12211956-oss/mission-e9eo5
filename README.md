#  = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() {
      return request.auth != null;
    }

    function profileExists() {
      return signedIn()
        && exists(/databases/$(database)/documents/users/$(request.auth.uid));
    }

    function myProfile() {
      return get(/databases/$(database)/documents/users/$(request.auth.uid)).data;
    }

    function isActive() {
      return profileExists() && myProfile().active == true;
    }

    function isAdmin() {
      return isActive() && myProfile().role == 'admin';
    }

    function isModerator() {
      return isActive() && myProfile().role in ['admin', 'moderator'];
    }

    match /users/{userId} {
      // Un membre ne lit que son propre profil. L'administrateur peut tous les lire.
      allow read: if isAdmin() || (isActive() && request.auth.uid == userId);

      // Aucun utilisateur ne peut fabriquer son propre profil ou s'attribuer un rôle.
      // Le premier administrateur doit être provisionné par une opération de confiance.
      allow create: if isAdmin()
        && request.resource.data.keys().hasOnly(['name', 'email', 'role', 'active', 'createdAt'])
        && request.resource.data.name is string
        && request.resource.data.email is string
        && request.resource.data.role == 'member'
        && request.resource.data.active == true;

      // L'administrateur ne peut modifier ici que le rôle et l'état actif.
      allow update: if isAdmin()
        && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['role', 'active'])
        && request.resource.data.role in ['admin', 'moderator', 'member']
        && request.resource.data.active is bool;

      allow delete: if isAdmin();
    }

    match /posts/{postId} {
      // Les membres actifs voient les publications approuvées; modérateurs voient aussi l'attente.
      allow read: if isActive() && (
        resource.data.status == 'published' || isModerator()
      );

      allow create: if isActive()