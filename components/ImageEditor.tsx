'use client'

import React, { useState, useRef, useEffect } from 'react';
import { Stage, Layer, Image as KonvaImage, Rect, Text, Line, Transformer } from 'react-konva';
import useImage from 'use-image';
import { toast } from 'sonner';
import { driver } from "driver.js";
import "driver.js/dist/driver.css";
import Toolbar from './Toolbar';
import Sidebar from './Sidebar';
import Header from './Header';
import { useTranslation } from 'react-i18next';

const ImageEditor = () => {
  const [image] = useImage('');
  const [tool, setTool] = useState('select');
  const [layers, setLayers] = useState([]);
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [colorFormat, setColorFormat] = useState('RGB');
  const [language, setLanguage] = useState('en');
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 600 });
  const [selectedColor, setSelectedColor] = useState('#000000');
  const [textInput, setTextInput] = useState('');
  const [fontSize, setFontSize] = useState(20);
  const [lines, setLines] = useState([]);
  const [isDrawing, setIsDrawing] = useState(false);
  const [selectedId, selectShape] = useState(null);
  const stageRef = useRef(null);
  const { t } = useTranslation();

  useEffect(() => {
    startTour();
  }, []);

  const startTour = () => {
    const driverObj = driver({
      showProgress: true,
      steps: [
        { element: '#toolbar', popover: { title: t('toolbar.title'), description: t('toolbar.description') } },
        { element: '#canvas', popover: { title: t('canvas.title'), description: t('canvas.description') } },
        { element: '#sidebar', popover: { title: t('sidebar.title'), description: t('sidebar.description') } },
      ]
    });
    driverObj.drive();
  };

  const handleToolChange = (newTool) => {
    setTool(newTool);
    toast.success(t('toolSelected', { tool: newTool }));
  };

  const handleLayerChange = (newLayers) => {
    setLayers(newLayers);
  };

  const handleExport = () => {
    if (stageRef.current) {
      const uri = stageRef.current.toDataURL();
      const link = document.createElement('a');
      link.download = 'image.png';
      link.href = uri;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      toast.success(t('exportSuccess'));
    }
  };

  const handleImageUpload = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new window.Image();
      img.src = e.target.result;
      img.onload = () => {
        setCanvasSize({ width: img.width, height: img.height });
        setLayers([{ id: 'image', visible: true, name: 'Image', image: img }]);
      };
    };
    reader.readAsDataURL(file);
  };

  const handleNewCanvas = (width, height) => {
    setCanvasSize({ width, height });
    setLayers([]);
  };

  const handleMouseDown = (e) => {
    if (tool === 'draw') {
      setIsDrawing(true);
      const pos = e.target.getStage().getPointerPosition();
      setLines([...lines, { tool, points: [pos.x, pos.y], color: selectedColor }]);
    } else if (tool === 'select') {
      // Check if clicked on an empty area
      const clickedOnEmpty = e.target === e.target.getStage();
      if (clickedOnEmpty) {
        selectShape(null);
      }
    }
  };

  const handleMouseMove = (e) => {
    if (!isDrawing) return;

    const stage = e.target.getStage();
    const point = stage.getPointerPosition();
    let lastLine = lines[lines.length - 1];
    lastLine.points = lastLine.points.concat([point.x, point.y]);

    lines.splice(lines.length - 1, 1, lastLine);
    setLines([...lines]);
  };

  const handleMouseUp = () => {
    setIsDrawing(false);
  };

  const handleTextDblClick = (e) => {
    const textNode = e.target;
    textNode.hide();
    const textPosition = textNode.absolutePosition();

    const textarea = document.createElement('textarea');
    document.body.appendChild(textarea);

    textarea.value = textNode.text();
    textarea.style.position = 'absolute';
    textarea.style.top = `${textPosition.y}px`;
    textarea.style.left = `${textPosition.x}px`;
    textarea.style.width = `${textNode.width()}px`;
    textarea.style.height = `${textNode.height()}px`;
    textarea.style.fontSize = `${textNode.fontSize()}px`;
    textarea.style.border = 'none';
    textarea.style.padding = '0px';
    textarea.style.margin = '0px';
    textarea.style.overflow = 'hidden';
    textarea.style.background = 'none';
    textarea.style.outline = 'none';
    textarea.style.resize = 'none';
    textarea.style.lineHeight = textNode.lineHeight();
    textarea.style.fontFamily = textNode.fontFamily();
    textarea.style.transformOrigin = 'left top';
    textarea.style.textAlign = textNode.align();
    textarea.style.color = textNode.fill();

    textarea.focus();

    textarea.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        textNode.text(textarea.value);
        document.body.removeChild(textarea);
        textNode.show();
      }
    });

    textarea.addEventListener('blur', function () {
      textNode.text(textarea.value);
      document.body.removeChild(textarea);
      textNode.show();
    });
  };

  return (
    <div className={`flex flex-col h-screen ${isDarkMode ? 'dark' : ''}`}>
      <Header 
        onImageUpload={handleImageUpload}
        onExport={handleExport}
        isDarkMode={isDarkMode}
        setIsDarkMode={setIsDarkMode}
        colorFormat={colorFormat}
        setColorFormat={setColorFormat}
        language={language}
        setLanguage={setLanguage}
        onNewCanvas={handleNewCanvas}
      />
      <div className="flex flex-1 overflow-hidden">
        <Toolbar onToolChange={handleToolChange} activeTool={tool} />
        <main className="flex-1 overflow-auto p-4">
          <div id="canvas" className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-4 max-w-full max-h-full overflow-auto">
            <Stage 
              width={canvasSize.width} 
              height={canvasSize.height} 
              ref={stageRef}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
            >
              <Layer>
                {layers.map((layer, index) => (
                  layer.visible && (
                    <KonvaImage
                      key={layer.id}
                      image={layer.image}
                      width={canvasSize.width}
                      height={canvasSize.height}
                    />
                  )
                ))}
                {lines.map((line, i) => (
                  <Line
                    key={i}
                    points={line.points}
                    stroke={line.color}
                    strokeWidth={5}
                    tension={0.5}
                    lineCap="round"
                    lineJoin="round"
                    globalCompositeOperation={
                      line.tool === 'eraser' ? 'destination-out' : 'source-over'
                    }
                  />
                ))}
                {tool === 'text' && (
                  <Text
                    x={20}
                    y={20}
                    text={textInput}
                    fontSize={fontSize}
                    fill={selectedColor}
                    draggable
                    onDblClick={handleTextDblClick}
                  />
                )}
              </Layer>
            </Stage>
          </div>
        </main>
        <Sidebar 
          layers={layers} 
          onLayerChange={handleLayerChange} 
          colorFormat={colorFormat}
          selectedColor={selectedColor}
          setSelectedColor={setSelectedColor}
          textInput={textInput}
          setTextInput={setTextInput}
          fontSize={fontSize}
          setFontSize={setFontSize}
          activeTool={tool}
        />
      </div>
    </div>
  );
};

export default ImageEditor;

