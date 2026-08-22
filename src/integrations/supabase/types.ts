export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.15"
  }
  public: {
    Tables: {
      audit_logs: {
        Row: {
          action: string
          actor_email: string | null
          created_at: string
          id: string
          ip: string | null
          result: string
          target_id: string | null
          target_label: string | null
          target_type: string | null
          user_agent: string | null
          user_id: string | null
          workspace_id: string | null
        }
        Insert: {
          action: string
          actor_email?: string | null
          created_at?: string
          id?: string
          ip?: string | null
          result?: string
          target_id?: string | null
          target_label?: string | null
          target_type?: string | null
          user_agent?: string | null
          user_id?: string | null
          workspace_id?: string | null
        }
        Update: {
          action?: string
          actor_email?: string | null
          created_at?: string
          id?: string
          ip?: string | null
          result?: string
          target_id?: string | null
          target_label?: string | null
          target_type?: string | null
          user_agent?: string | null
          user_id?: string | null
          workspace_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "audit_logs_workspace_id_fkey"
            columns: ["workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      encryption_keys: {
        Row: {
          created_at: string
          id: string
          key_version: number
          provider: string
          workspace_id: string
          wrapped_dek: string
        }
        Insert: {
          created_at?: string
          id?: string
          key_version?: number
          provider?: string
          workspace_id: string
          wrapped_dek: string
        }
        Update: {
          created_at?: string
          id?: string
          key_version?: number
          provider?: string
          workspace_id?: string
          wrapped_dek?: string
        }
        Relationships: [
          {
            foreignKeyName: "encryption_keys_workspace_id_fkey"
            columns: ["workspace_id"]
            isOneToOne: true
            referencedRelation: "workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      oidc_group_mappings: {
        Row: {
          app_role: Database["public"]["Enums"]["app_role"] | null
          created_at: string
          id: string
          oidc_group: string
          provider_id: string | null
          workspace_id: string | null
          workspace_role: Database["public"]["Enums"]["workspace_role"] | null
        }
        Insert: {
          app_role?: Database["public"]["Enums"]["app_role"] | null
          created_at?: string
          id?: string
          oidc_group: string
          provider_id?: string | null
          workspace_id?: string | null
          workspace_role?: Database["public"]["Enums"]["workspace_role"] | null
        }
        Update: {
          app_role?: Database["public"]["Enums"]["app_role"] | null
          created_at?: string
          id?: string
          oidc_group?: string
          provider_id?: string | null
          workspace_id?: string | null
          workspace_role?: Database["public"]["Enums"]["workspace_role"] | null
        }
        Relationships: [
          {
            foreignKeyName: "oidc_group_mappings_provider_id_fkey"
            columns: ["provider_id"]
            isOneToOne: false
            referencedRelation: "oidc_providers"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "oidc_group_mappings_workspace_id_fkey"
            columns: ["workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      oidc_providers: {
        Row: {
          authorization_endpoint: string | null
          client_id: string | null
          client_secret_ciphertext: string | null
          created_at: string
          enabled: boolean
          id: string
          issuer_url: string | null
          logout_uri: string | null
          name: string
          permission_mode: string
          redirect_uri: string | null
          scopes: string
          token_endpoint: string | null
          updated_at: string
          userinfo_endpoint: string | null
        }
        Insert: {
          authorization_endpoint?: string | null
          client_id?: string | null
          client_secret_ciphertext?: string | null
          created_at?: string
          enabled?: boolean
          id?: string
          issuer_url?: string | null
          logout_uri?: string | null
          name?: string
          permission_mode?: string
          redirect_uri?: string | null
          scopes?: string
          token_endpoint?: string | null
          updated_at?: string
          userinfo_endpoint?: string | null
        }
        Update: {
          authorization_endpoint?: string | null
          client_id?: string | null
          client_secret_ciphertext?: string | null
          created_at?: string
          enabled?: boolean
          id?: string
          issuer_url?: string | null
          logout_uri?: string | null
          name?: string
          permission_mode?: string
          redirect_uri?: string | null
          scopes?: string
          token_endpoint?: string | null
          updated_at?: string
          userinfo_endpoint?: string | null
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          display_name: string | null
          email: string | null
          id: string
          lock_timeout_minutes: number
          theme: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          display_name?: string | null
          email?: string | null
          id: string
          lock_timeout_minutes?: number
          theme?: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          display_name?: string | null
          email?: string | null
          id?: string
          lock_timeout_minutes?: number
          theme?: string
          updated_at?: string
        }
        Relationships: []
      }
      secret_fields: {
        Row: {
          ciphertext: string
          created_at: string
          field_type: string
          id: string
          is_sensitive: boolean
          label: string
          position: number
          secret_id: string
        }
        Insert: {
          ciphertext: string
          created_at?: string
          field_type?: string
          id?: string
          is_sensitive?: boolean
          label: string
          position?: number
          secret_id: string
        }
        Update: {
          ciphertext?: string
          created_at?: string
          field_type?: string
          id?: string
          is_sensitive?: boolean
          label?: string
          position?: number
          secret_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "secret_fields_secret_id_fkey"
            columns: ["secret_id"]
            isOneToOne: false
            referencedRelation: "secrets"
            referencedColumns: ["id"]
          },
        ]
      }
      secret_versions: {
        Row: {
          action: string
          changed_at: string
          changed_by: string | null
          changed_fields: string[]
          id: string
          secret_id: string
          version: number
        }
        Insert: {
          action: string
          changed_at?: string
          changed_by?: string | null
          changed_fields?: string[]
          id?: string
          secret_id: string
          version?: number
        }
        Update: {
          action?: string
          changed_at?: string
          changed_by?: string | null
          changed_fields?: string[]
          id?: string
          secret_id?: string
          version?: number
        }
        Relationships: [
          {
            foreignKeyName: "secret_versions_secret_id_fkey"
            columns: ["secret_id"]
            isOneToOne: false
            referencedRelation: "secrets"
            referencedColumns: ["id"]
          },
        ]
      }
      secrets: {
        Row: {
          created_at: string
          created_by: string | null
          deleted_at: string | null
          description: string | null
          expires_at: string | null
          favorite: boolean
          id: string
          name: string
          notify_before_days: number | null
          tags: string[]
          type: Database["public"]["Enums"]["secret_type"]
          updated_at: string
          updated_by: string | null
          url: string | null
          username: string | null
          workspace_id: string
        }
        Insert: {
          created_at?: string
          created_by?: string | null
          deleted_at?: string | null
          description?: string | null
          expires_at?: string | null
          favorite?: boolean
          id?: string
          name: string
          notify_before_days?: number | null
          tags?: string[]
          type?: Database["public"]["Enums"]["secret_type"]
          updated_at?: string
          updated_by?: string | null
          url?: string | null
          username?: string | null
          workspace_id: string
        }
        Update: {
          created_at?: string
          created_by?: string | null
          deleted_at?: string | null
          description?: string | null
          expires_at?: string | null
          favorite?: boolean
          id?: string
          name?: string
          notify_before_days?: number | null
          tags?: string[]
          type?: Database["public"]["Enums"]["secret_type"]
          updated_at?: string
          updated_by?: string | null
          url?: string | null
          username?: string | null
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "secrets_workspace_id_fkey"
            columns: ["workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      user_roles: {
        Row: {
          created_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
      workspace_members: {
        Row: {
          created_at: string
          id: string
          managed_by_oidc: boolean
          role: Database["public"]["Enums"]["workspace_role"]
          user_id: string
          workspace_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          managed_by_oidc?: boolean
          role?: Database["public"]["Enums"]["workspace_role"]
          user_id: string
          workspace_id: string
        }
        Update: {
          created_at?: string
          id?: string
          managed_by_oidc?: boolean
          role?: Database["public"]["Enums"]["workspace_role"]
          user_id?: string
          workspace_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "workspace_members_workspace_id_fkey"
            columns: ["workspace_id"]
            isOneToOne: false
            referencedRelation: "workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      workspaces: {
        Row: {
          allow_viewer_reveal: boolean
          created_at: string
          deleted_at: string | null
          description: string | null
          disabled: boolean
          id: string
          is_personal: boolean
          name: string
          owner_id: string
          updated_at: string
        }
        Insert: {
          allow_viewer_reveal?: boolean
          created_at?: string
          deleted_at?: string | null
          description?: string | null
          disabled?: boolean
          id?: string
          is_personal?: boolean
          name: string
          owner_id: string
          updated_at?: string
        }
        Update: {
          allow_viewer_reveal?: boolean
          created_at?: string
          deleted_at?: string | null
          description?: string | null
          disabled?: boolean
          id?: string
          is_personal?: boolean
          name?: string
          owner_id?: string
          updated_at?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
      is_workspace_member: {
        Args: { _user_id: string; _workspace_id: string }
        Returns: boolean
      }
      workspace_role_of: {
        Args: { _user_id: string; _workspace_id: string }
        Returns: Database["public"]["Enums"]["workspace_role"]
      }
    }
    Enums: {
      app_role: "SUPER_ADMIN" | "USER"
      secret_type:
        | "LOGIN"
        | "API_KEY"
        | "TOKEN"
        | "SSH_KEY"
        | "DATABASE"
        | "SECURE_NOTE"
        | "CUSTOM"
      workspace_role: "OWNER" | "ADMIN" | "EDITOR" | "VIEWER"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["SUPER_ADMIN", "USER"],
      secret_type: [
        "LOGIN",
        "API_KEY",
        "TOKEN",
        "SSH_KEY",
        "DATABASE",
        "SECURE_NOTE",
        "CUSTOM",
      ],
      workspace_role: ["OWNER", "ADMIN", "EDITOR", "VIEWER"],
    },
  },
} as const
