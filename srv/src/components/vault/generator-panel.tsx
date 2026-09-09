import { useCallback, useEffect, useMemo, useState } from "react";
import { Check, Copy, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  generateApiToken,
  generateBase64,
  generateHex,
  generatePassword,
  generateUuidV4,
  passwordEntropy,
  strengthLabel,
} from "@/lib/generators";
import { cn } from "@/lib/utils";

function useCopyWithAutoClear() {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      toast.success("Copié — le presse-papiers sera vidé dans 20 s");
      setTimeout(() => setCopied(false), 1500);
      // Best-effort clipboard auto-clear.
      setTimeout(() => {
        void navigator.clipboard.writeText("").catch(() => undefined);
      }, 20_000);
    } catch {
      toast.error("Copie impossible dans ce navigateur");
    }
  }, []);
  return { copied, copy };
}

function OutputRow({ value, copied, onCopy, onRegenerate }: {
  value: string;
  copied: boolean;
  onCopy: () => void;
  onRegenerate: () => void;
}) {
  return (
    <div className="flex items-center gap-2 rounded-lg border bg-muted/40 p-3">
      <code className="secret-value flex-1 text-sm text-foreground">{value}</code>
      <Button variant="ghost" size="icon" onClick={onRegenerate} title="Régénérer">
        <RefreshCw className="h-4 w-4" />
      </Button>
      <Button variant="ghost" size="icon" onClick={onCopy} title="Copier">
        {copied ? <Check className="h-4 w-4 text-success" /> : <Copy className="h-4 w-4" />}
      </Button>
    </div>
  );
}

function StrengthMeter({ value }: { value: string }) {
  const entropy = useMemo(() => passwordEntropy(value), [value]);
  const { label, level } = strengthLabel(entropy);
  const colors = [
    "bg-destructive",
    "bg-destructive",
    "bg-warning",
    "bg-success",
    "bg-success",
  ];
  return (
    <div className="space-y-1.5">
      <div className="flex gap-1">
        {[0, 1, 2, 3].map((i) => (
          <div
            key={i}
            className={cn(
              "h-1.5 flex-1 rounded-full bg-muted transition-colors",
              i < level && colors[level],
            )}
          />
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        Force : <span className="font-medium text-foreground">{label}</span>
        {entropy > 0 && <span> (~{entropy} bits d'entropie)</span>}
      </p>
    </div>
  );
}

function PasswordTab() {
  const [length, setLength] = useState(20);
  const [lowercase, setLowercase] = useState(true);
  const [uppercase, setUppercase] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(true);
  const [customChars, setCustomChars] = useState("");
  const [value, setValue] = useState("");
  const { copied, copy } = useCopyWithAutoClear();

  const regenerate = useCallback(() => {
    setValue(
      generatePassword({ length, lowercase, uppercase, digits, symbols, excludeAmbiguous, customChars }),
    );
  }, [length, lowercase, uppercase, digits, symbols, excludeAmbiguous, customChars]);

  useEffect(() => {
    regenerate();
  }, [regenerate]);

  return (
    <div className="space-y-5">
      <OutputRow value={value} copied={copied} onCopy={() => void copy(value)} onRegenerate={regenerate} />
      <StrengthMeter value={value} />
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label>Longueur</Label>
          <span className="font-mono text-sm text-muted-foreground">{length}</span>
        </div>
        <Slider min={8} max={64} step={1} value={[length]} onValueChange={([v]) => setLength(v ?? 20)} />
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        {[
          ["Minuscules (a-z)", lowercase, setLowercase],
          ["Majuscules (A-Z)", uppercase, setUppercase],
          ["Chiffres (0-9)", digits, setDigits],
          ["Symboles", symbols, setSymbols],
          ["Exclure ambigus (l, 1, O, 0)", excludeAmbiguous, setExcludeAmbiguous],
        ].map(([label, checked, setter]) => (
          <label key={label as string} className="flex items-center gap-2 text-sm">
            <Switch checked={checked as boolean} onCheckedChange={setter as (v: boolean) => void} />
            <span className="text-muted-foreground">{label as string}</span>
          </label>
        ))}
      </div>
      <div className="space-y-2">
        <Label htmlFor="custom-chars">Caractères personnalisés (ajoutés au jeu)</Label>
        <Input
          id="custom-chars"
          value={customChars}
          onChange={(e) => setCustomChars(e.target.value)}
          placeholder="ex. #€"
          className="font-mono"
        />
      </div>
    </div>
  );
}

function EncodingTab({ kind }: { kind: "base64" | "hex" }) {
  const [bytes, setBytes] = useState(32);
  const [value, setValue] = useState("");
  const { copied, copy } = useCopyWithAutoClear();

  const regenerate = useCallback(() => {
    setValue(kind === "base64" ? generateBase64(bytes) : generateHex(bytes));
  }, [kind, bytes]);

  useEffect(() => {
    regenerate();
  }, [regenerate]);

  return (
    <div className="space-y-5">
      <OutputRow value={value} copied={copied} onCopy={() => void copy(value)} onRegenerate={regenerate} />
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label>Octets aléatoires</Label>
          <span className="font-mono text-sm text-muted-foreground">{bytes}</span>
        </div>
        <Slider min={8} max={128} step={8} value={[bytes]} onValueChange={([v]) => setBytes(v ?? 32)} />
      </div>
    </div>
  );
}

function UuidTab() {
  const [value, setValue] = useState("");
  const { copied, copy } = useCopyWithAutoClear();
  const regenerate = useCallback(() => setValue(generateUuidV4()), []);
  useEffect(() => {
    regenerate();
  }, [regenerate]);
  return (
    <OutputRow value={value} copied={copied} onCopy={() => void copy(value)} onRegenerate={regenerate} />
  );
}

function ApiTokenTab() {
  const [prefix, setPrefix] = useState("sk");
  const [length, setLength] = useState(40);
  const [value, setValue] = useState("");
  const { copied, copy } = useCopyWithAutoClear();

  const regenerate = useCallback(() => {
    setValue(generateApiToken(prefix, length));
  }, [prefix, length]);

  useEffect(() => {
    regenerate();
  }, [regenerate]);

  return (
    <div className="space-y-5">
      <OutputRow value={value} copied={copied} onCopy={() => void copy(value)} onRegenerate={regenerate} />
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="token-prefix">Préfixe</Label>
          <Input id="token-prefix" value={prefix} onChange={(e) => setPrefix(e.target.value)} className="font-mono" />
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label>Longueur</Label>
            <span className="font-mono text-sm text-muted-foreground">{length}</span>
          </div>
          <Slider min={16} max={96} step={4} value={[length]} onValueChange={([v]) => setLength(v ?? 40)} />
        </div>
      </div>
    </div>
  );
}

export function GeneratorPanel() {
  return (
    <Tabs defaultValue="password">
      <TabsList className="flex-wrap">
        <TabsTrigger value="password">Mot de passe</TabsTrigger>
        <TabsTrigger value="base64">Base64</TabsTrigger>
        <TabsTrigger value="hex">Hexadécimal</TabsTrigger>
        <TabsTrigger value="uuid">UUID v4</TabsTrigger>
        <TabsTrigger value="token">Token API</TabsTrigger>
      </TabsList>
      <div className="mt-6">
        <TabsContent value="password"><PasswordTab /></TabsContent>
        <TabsContent value="base64"><EncodingTab kind="base64" /></TabsContent>
        <TabsContent value="hex"><EncodingTab kind="hex" /></TabsContent>
        <TabsContent value="uuid"><UuidTab /></TabsContent>
        <TabsContent value="token"><ApiTokenTab /></TabsContent>
      </div>
    </Tabs>
  );
}
