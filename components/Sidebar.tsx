import React from 'react';
import { HexColorPicker } from 'react-colorful';
import { useTranslation } from 'react-i18next';
import { Slider } from './ui/slider';
import { Input } from './ui/input';
import { Label } from './ui/label';

const Sidebar = ({ 
  layers, 
  onLayerChange, 
  colorFormat, 
  selectedColor, 
  setSelectedColor, 
  textInput, 
  setTextInput, 
  fontSize, 
  setFontSize,
  activeTool
}) => {
  const { t } = useTranslation();

  const formatColor = (hex) => {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);

    switch (colorFormat) {
      case 'RGB':
        return `rgb(${r}, ${g}, ${b})`;
      case 'CMYK':
        const k = 1 - Math.max(r / 255, g / 255, b / 255);
        const c = (1 - r / 255 - k) / (1 - k);
        const m = (1 - g / 255 - k) / (1 - k);
        const y = (1 - b / 255 - k) / (1 - k);
        return `cmyk(${Math.round(c * 100)}%, ${Math.round(m * 100)}%, ${Math.round(y * 100)}%, ${Math.round(k * 100)}%)`;
      case 'HSL':
        const max = Math.max(r, g, b);
        const min = Math.min(r, g, b);
        let h, s, l = (max + min) / 2;

        if (max === min) {
          h = s = 0;
        } else {
          const d = max - min;
          s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
          switch (max) {
            case r: h = (g - b) / d + (g < b ? 6 : 0); break;
            case g: h = (b - r) / d + 2; break;
            case b: h = (r - g) / d + 4; break;
          }
          h /= 6;
        }

        return `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`;
      default:
        return hex;
    }
  };

  return (
    <div id="sidebar" className="w-64 bg-white dark:bg-gray-800 shadow-lg p-4 overflow-y-auto">
      <h2 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">{t('layers')}</h2>
      <ul>
        {layers.map((layer, index) => (
          <li key={index} className="mb-2 flex items-center">
            <input
              type="checkbox"
              checked={layer.visible}
              onChange={() => {
                const newLayers = [...layers];
                newLayers[index].visible = !newLayers[index].visible;
                onLayerChange(newLayers);
              }}
              className="mr-2"
            />
            <span className="text-gray-700 dark:text-gray-300">{layer.name}</span>
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
            <span>{fontSize}px</span>
          </div>
        </>
      )}
      {activeTool === 'draw' && (
        <>
          <h2 className="text-lg font-semibold my-4 text-gray-900 dark:text-white">{t('brush')}</h2>
          <div className="space-y-2">
            <Label htmlFor="brushSize">{t('brushSize')}</Label>
            <Slider
              id="brushSize"
              min={1}
              max={50}
              step={1}
              value={[5]}
              onValueChange={(value) => console.log('Brush size:', value[0])}
            />
          </div>
        </>
      )}
    </div>
  );
};

export default Sidebar;

