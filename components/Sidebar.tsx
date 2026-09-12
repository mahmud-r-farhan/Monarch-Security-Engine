import React from 'react';
import { HexColorPicker } from 'react-colorful';
import { useTranslation } from 'react-i18next';
import { Slider } from './ui/slider';
import { Input } from './ui/input';
import { Label } from './ui/label';

export interface LayerItem {
  id: string;
  name: string;
  visible: boolean;
  image?: HTMLImageElement;
  x?: number;
  y?: number;
}

export interface SidebarProps {
  layers: LayerItem[];
  onLayerChange: (layers: LayerItem[]) => void;
  colorFormat: string;
  selectedColor: string;
  setSelectedColor: (color: string) => void;
  textInput: string;
  setTextInput: (text: string) => void;
  fontSize: number;
  setFontSize: (size: number) => void;
  brushSize: number;
  setBrushSize: (size: number) => void;
  activeTool: string;
}

const Sidebar: React.FC<SidebarProps> = ({
  layers,
  onLayerChange,
  colorFormat,
  selectedColor,
  setSelectedColor,
  textInput,
  setTextInput,
  fontSize,
  setFontSize,
  brushSize,
  setBrushSize,
  activeTool
}) => {
  const { t } = useTranslation();

  const formatColor = (hex: string): string => {
    if (!hex || !hex.startsWith('#') || hex.length < 7) {
      return hex || '';
    }
    const r = parseInt(hex.slice(1, 3), 16) || 0;
    const g = parseInt(hex.slice(3, 5), 16) || 0;
    const b = parseInt(hex.slice(5, 7), 16) || 0;

    switch (colorFormat) {
      case 'RGB':
        return `rgb(${r}, ${g}, ${b})`;
      case 'CMYK': {
        const rNorm = r / 255;
        const gNorm = g / 255;
        const bNorm = b / 255;
        const k = 1 - Math.max(rNorm, gNorm, bNorm);
        if (k === 1) {
          return 'cmyk(0%, 0%, 0%, 100%)';
        }
        const c = (1 - rNorm - k) / (1 - k);
        const m = (1 - gNorm - k) / (1 - k);
        const y = (1 - bNorm - k) / (1 - k);
        return `cmyk(${Math.round(c * 100)}%, ${Math.round(m * 100)}%, ${Math.round(y * 100)}%, ${Math.round(k * 100)}%)`;
      }
      case 'HSL': {
        const rNorm = r / 255;
        const gNorm = g / 255;
        const bNorm = b / 255;
        const max = Math.max(rNorm, gNorm, bNorm);
        const min = Math.min(rNorm, gNorm, bNorm);
        let h = 0;
        let s = 0;
        const l = (max + min) / 2;

        if (max !== min) {
          const d = max - min;
          s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
          switch (max) {
            case rNorm: h = (gNorm - bNorm) / d + (gNorm < bNorm ? 6 : 0); break;
            case gNorm: h = (bNorm - rNorm) / d + 2; break;
            case bNorm: h = (rNorm - gNorm) / d + 4; break;
          }
          h /= 6;
        }

        return `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`;
      }
      default:
        return hex;
    }
  };

  return (
    <div id="sidebar" className="w-64 bg-white dark:bg-gray-800 shadow-lg p-4 overflow-y-auto">
      <h2 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">{t('layers')}</h2>
      <ul>
        {layers.map((layer, index) => (
          <li key={layer.id || index} className="mb-2 flex items-center justify-between">
            <label className="flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={layer.visible}
                onChange={() => {
                  const newLayers = [...layers];
                  newLayers[index] = { ...newLayers[index], visible: !newLayers[index].visible };
                  onLayerChange(newLayers);
                }}
                className="mr-2"
              />
              <span className="text-gray-700 dark:text-gray-300">{layer.name}</span>
            </label>
          </li>
        ))}
      </ul>

      <h2 className="text-lg font-semibold my-4 text-gray-900 dark:text-white">{t('color')}</h2>
      <HexColorPicker color={selectedColor} onChange={setSelectedColor} />
      <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
        {t('selectedColor')}: {formatColor(selectedColor)}
      </p>

      {activeTool === 'text' && (
        <>
          <h2 className="text-lg font-semibold my-4 text-gray-900 dark:text-white">{t('text')}</h2>
          <div className="space-y-2">
            <Label htmlFor="textInput">{t('textInput')}</Label>
            <Input
              id="textInput"
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
            />
            <Label htmlFor="fontSize">{t('fontSize')}</Label>
            <Slider
              id="fontSize"
              min={8}
              max={72}
              step={1}
              value={[fontSize]}
              onValueChange={(value) => setFontSize(value[0])}
            />
            <span className="text-xs text-gray-500">{fontSize}px</span>
          </div>
        </>
      )}

      {(activeTool === 'draw' || activeTool === 'eraser') && (
        <>
          <h2 className="text-lg font-semibold my-4 text-gray-900 dark:text-white">{t('brush')}</h2>
          <div className="space-y-2">
            <Label htmlFor="brushSize">{t('brushSize')}</Label>
            <Slider
              id="brushSize"
              min={1}
              max={50}
              step={1}
              value={[brushSize]}
              onValueChange={(value) => setBrushSize(value[0])}
            />
            <span className="text-xs text-gray-500">{brushSize}px</span>
          </div>
        </>
      )}
    </div>
  );
};

export default Sidebar;
